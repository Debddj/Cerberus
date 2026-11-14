import asyncio
import json
import time
from unittest.mock import patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from cerberus.config import settings
from cerberus.proxy.challenge_manager import (
    ChallengeExpiredError,
    ChallengeManager,
    ChallengeRequest,
    ChallengeStatus,
    StepUpAuthError,
    StepUpTokenManager,
    WebhookDispatcher,
)
from cerberus.proxy.models import EventDecision
from cerberus.proxy.server import CerberusProxyEngine, app

# ============================================================================
# 1. Webhook Dispatcher & HMAC-SHA256 Signature Tests
# ============================================================================


def test_generic_webhook_payload_structure():
    """Verify generic webhook payload conforms to standard schema."""
    challenge = ChallengeRequest(
        challenge_id="chg_test123",
        event_id="evt_abc",
        session_id="sess_xyz",
        agent_id="agent_smith",
        tool_name="database_exec",
        tool_server="db-mcp",
        parameters={"query": "SELECT * FROM users"},
        risk_score=0.65,
        risk_factors=["anomaly:high_entropy", "novel_tool"],
        expires_at=time.time() + 60,
        timeout_seconds=60.0,
        status=ChallengeStatus.PENDING,
        step_up_token="token_sample_123",
    )
    dispatcher = WebhookDispatcher(
        webhook_url="https://example.com/webhook", webhook_format="generic"
    )
    payload = dispatcher.format_payload(challenge, event_type="challenge.created")

    assert payload["event"] == "challenge.created"
    assert payload["challenge_id"] == "chg_test123"
    assert payload["agent_id"] == "agent_smith"
    assert payload["tool_name"] == "database_exec"
    assert payload["tool_server"] == "db-mcp"
    assert payload["risk_score"] == 0.65
    assert "novel_tool" in payload["risk_factors"]
    assert payload["step_up_token"] == "token_sample_123"
    assert payload["status"] == "pending"
    assert payload["parameters"] == {"query": "SELECT * FROM users"}


def test_slack_webhook_payload_structure():
    """Verify Slack Block Kit webhook payload structure."""
    challenge = ChallengeRequest(
        challenge_id="chg_slack123",
        event_id="evt_slack",
        session_id="sess_slack",
        agent_id="agent_coder",
        tool_name="aws_create_user",
        tool_server="aws-mcp",
        parameters={"username": "attacker"},
        risk_score=0.88,
        risk_factors=["sensitive_privilege_escalation"],
        expires_at=time.time() + 60,
        timeout_seconds=60.0,
        status=ChallengeStatus.PENDING,
        step_up_token="step_token_slack",
    )
    dispatcher = WebhookDispatcher(
        webhook_url="https://hooks.slack.com/services/T00/B00/X00",
        webhook_format="slack",
    )
    payload = dispatcher.format_payload(challenge)

    assert "text" in payload
    assert "blocks" in payload
    assert len(payload["blocks"]) >= 3
    # Header block
    assert payload["blocks"][0]["type"] == "header"
    # Section block with fields
    fields = payload["blocks"][1]["fields"]
    field_texts = [f["text"] for f in fields]
    assert any("chg_slack123" in txt for txt in field_texts)
    assert any("agent_coder" in txt for txt in field_texts)
    assert any("aws_create_user" in txt for txt in field_texts)
    assert any("0.88" in txt for txt in field_texts)


def test_hmac_sha256_signature_header_generation_and_verification():
    """Verify HMAC-SHA256 signature calculation and verification."""
    secret = "super-secret-webhook-signing-key-9988"
    dispatcher = WebhookDispatcher(
        webhook_url="https://example.com/webhook",
        webhook_secret=secret,
    )

    body_bytes = b'{"challenge_id":"chg_test","action":"approve"}'
    headers = dispatcher.sign_payload(body_bytes)

    assert "X-Cerberus-Signature" in headers
    assert "X-Cerberus-Timestamp" in headers
    assert headers["X-Cerberus-Signature"].startswith("sha256=")

    # 1. Verification succeeds with matching secret & timestamp
    valid, msg = WebhookDispatcher.verify_signature(
        payload_bytes=body_bytes,
        signature_header=headers["X-Cerberus-Signature"],
        secret=secret,
        timestamp_header=headers["X-Cerberus-Timestamp"],
    )
    assert valid is True
    assert "successfully" in msg

    # 2. Verification fails with mismatched secret
    invalid_secret, err = WebhookDispatcher.verify_signature(
        payload_bytes=body_bytes,
        signature_header=headers["X-Cerberus-Signature"],
        secret="wrong-secret-key",
        timestamp_header=headers["X-Cerberus-Timestamp"],
    )
    assert invalid_secret is False
    assert "failed" in err

    # 3. Verification fails with tampered payload
    tampered_bytes = b'{"challenge_id":"chg_test","action":"tampered"}'
    tampered, err = WebhookDispatcher.verify_signature(
        payload_bytes=tampered_bytes,
        signature_header=headers["X-Cerberus-Signature"],
        secret=secret,
        timestamp_header=headers["X-Cerberus-Timestamp"],
    )
    assert tampered is False
    assert "failed" in err

    # 4. Verification fails with expired timestamp drift
    stale_ts = str(int(time.time()) - 400)
    stale, err = WebhookDispatcher.verify_signature(
        payload_bytes=body_bytes,
        signature_header=headers["X-Cerberus-Signature"],
        secret=secret,
        timestamp_header=stale_ts,
        max_age_seconds=300.0,
    )
    assert stale is False
    assert "drift exceeds" in err


@pytest.mark.asyncio
async def test_webhook_dispatch_generic_success():
    """Verify successful dispatch to external generic webhook with verified signature."""
    secret = "signing-secret-77"
    received_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        received_requests.append(request)
        return httpx.Response(200, json={"status": "received"})

    mock_transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=mock_transport) as mock_client:
        dispatcher = WebhookDispatcher(
            webhook_url="https://secops.corp.internal/challenges",
            webhook_secret=secret,
            webhook_format="generic",
            client=mock_client,
        )

        chg = ChallengeRequest(
            challenge_id="chg_dispatch_1",
            event_id="evt_1",
            session_id="sess_1",
            agent_id="agent_1",
            tool_name="bash_eval",
            tool_server="code-mcp",
            parameters={"cmd": "ls -la"},
            risk_score=0.60,
            expires_at=time.time() + 60,
            status=ChallengeStatus.PENDING,
            step_up_token="token_xyz",
        )

        ok = await dispatcher.dispatch(chg)
        assert ok is True
        assert len(received_requests) == 1

        req = received_requests[0]
        sig_header = req.headers["x-cerberus-signature"]
        ts_header = req.headers["x-cerberus-timestamp"]
        valid, _ = WebhookDispatcher.verify_signature(
            payload_bytes=req.content,
            signature_header=sig_header,
            secret=secret,
            timestamp_header=ts_header,
        )
        assert valid is True
        parsed = json.loads(req.content)
        assert parsed["challenge_id"] == "chg_dispatch_1"


@pytest.mark.asyncio
async def test_webhook_dispatch_slack_success():
    """Verify dispatch format for Slack webhooks."""
    received = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(200, text="ok")

    mock_transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=mock_transport) as mock_client:
        dispatcher = WebhookDispatcher(
            webhook_url="https://hooks.slack.com/services/T1/B1/X1",
            webhook_format="slack",
            client=mock_client,
        )

        chg = ChallengeRequest(
            challenge_id="chg_slack_dispatch",
            event_id="evt_slack_1",
            session_id="sess_slack_1",
            agent_id="agent_slack",
            tool_name="s3_delete_bucket",
            tool_server="aws-mcp",
            risk_score=0.95,
            expires_at=time.time() + 60,
            status=ChallengeStatus.PENDING,
        )

        ok = await dispatcher.dispatch(chg)
        assert ok is True
        parsed = json.loads(received[0].content)
        assert "blocks" in parsed
        assert "s3_delete_bucket" in parsed["text"]


@pytest.mark.asyncio
async def test_webhook_dispatch_error_handled_gracefully():
    """Verify that network or HTTP failures in webhook delivery do not crash the caller."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    mock_transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=mock_transport) as mock_client:
        dispatcher = WebhookDispatcher(
            webhook_url="https://flaky-webhook.internal",
            client=mock_client,
        )
        chg = ChallengeRequest(
            challenge_id="chg_fail",
            event_id="e",
            session_id="s",
            agent_id="a",
            tool_name="t",
            tool_server="srv",
            expires_at=time.time() + 60,
        )
        ok = await dispatcher.dispatch(chg)
        assert ok is False


# ============================================================================
# 2. Step-Up Authentication Tokens & Anti-Replay Tests
# ============================================================================


def test_step_up_token_issuance_and_verification():
    """Verify step-up approval token generation and validation."""
    mgr = StepUpTokenManager(secret_key="unit-test-secret-key-1234")
    token = mgr.issue_token(
        challenge_id="chg_step_101",
        operator_id="secops_alice",
        action="approve",
        ttl_seconds=300,
    )

    valid, data, _msg = mgr.verify_token(
        token=token,
        expected_challenge_id="chg_step_101",
        expected_action="approve",
    )
    assert valid is True
    assert data["challenge_id"] == "chg_step_101"
    assert data["operator_id"] == "secops_alice"
    assert data["action"] == "approve"
    assert data["expires_at"] > time.time()


def test_step_up_token_invalid_signature():
    """Verify that tampered tokens fail cryptographic signature check."""
    mgr = StepUpTokenManager(secret_key="key-A")
    token = mgr.issue_token(challenge_id="chg_sec", action="approve")

    other_mgr = StepUpTokenManager(secret_key="key-B")
    valid, _, msg = other_mgr.verify_token(token=token, expected_challenge_id="chg_sec")
    assert valid is False
    assert "signature" in msg.lower()


def test_step_up_token_expired():
    """Verify expired step-up tokens are rejected."""
    mgr = StepUpTokenManager(secret_key="test-key")
    # Issue token that already expired 10 seconds ago
    token = mgr.issue_token(challenge_id="chg_exp", action="approve", ttl_seconds=-10)

    valid, _, msg = mgr.verify_token(token=token, expected_challenge_id="chg_exp")
    assert valid is False
    assert "expired" in msg.lower()


def test_step_up_token_challenge_binding():
    """Verify token bound to challenge A cannot be used on challenge B."""
    mgr = StepUpTokenManager(secret_key="test-key")
    token_a = mgr.issue_token(challenge_id="chg_AAA", action="approve")

    valid, _, msg = mgr.verify_token(token=token_a, expected_challenge_id="chg_BBB")
    assert valid is False
    assert "mismatch" in msg.lower()


def test_step_up_token_action_binding():
    """Verify token bound to reject cannot be used to approve."""
    mgr = StepUpTokenManager(secret_key="test-key")
    token_reject = mgr.issue_token(challenge_id="chg_act", action="reject")

    valid, _, msg = mgr.verify_token(
        token=token_reject, expected_challenge_id="chg_act", expected_action="approve"
    )
    assert valid is False
    assert "mismatch" in msg.lower()


def test_step_up_token_anti_replay_single_use():
    """Verify anti-replay protection: a consumed step-up token cannot be used again."""
    mgr = StepUpTokenManager(secret_key="anti-replay-secret")
    token = mgr.issue_token(challenge_id="chg_replay", action="approve")

    # First check: valid
    valid, _, _ = mgr.verify_token(token=token, expected_challenge_id="chg_replay")
    assert valid is True

    # Consume the token
    mgr.consume_token(token)
    assert mgr.is_token_consumed(token) is True

    # Second check: fails with replay detection
    valid_second, _, err = mgr.verify_token(token=token, expected_challenge_id="chg_replay")
    assert valid_second is False
    assert "replay" in err.lower()


def test_bearer_token_authorization():
    """Verify administrator bearer authorization validation."""
    mgr = StepUpTokenManager(
        secret_key="key",
        allowed_bearer_tokens=["admin-secret-token-999"],
    )

    assert mgr.verify_bearer_token("Bearer admin-secret-token-999") is True
    assert mgr.verify_bearer_token("admin-secret-token-999") is True
    assert mgr.verify_bearer_token("Bearer wrong-token") is False
    assert mgr.verify_bearer_token(None) is False


def test_validate_approval_credentials():
    """Verify validate_approval_credentials handles both step-up token and bearer auth."""
    mgr = StepUpTokenManager(
        secret_key="key",
        allowed_bearer_tokens=["admin-root-token"],
    )
    token = mgr.issue_token(challenge_id="chg_cred", operator_id="bob", action="approve")

    # 1. Bearer auth succeeds
    valid_b, ident_b, _ = mgr.validate_approval_credentials(
        challenge_id="chg_cred", bearer_token="Bearer admin-root-token"
    )
    assert valid_b is True
    assert "bearer" in ident_b

    # 2. Step-up token auth succeeds
    valid_t, ident_t, _ = mgr.validate_approval_credentials(
        challenge_id="chg_cred", step_up_token=token
    )
    assert valid_t is True
    assert ident_t == "bob"

    # 3. Missing both credentials fails
    valid_none, _, msg = mgr.validate_approval_credentials(challenge_id="chg_cred")
    assert valid_none is False
    assert "requires" in msg


# ============================================================================
# 3. Strict Fail-Closed Timeouts & Challenge Manager Lifecycle Tests
# ============================================================================


@pytest.mark.asyncio
async def test_strict_fail_closed_on_timeout():
    """Strict fail-closed timeout: unapproved challenge deterministically fails closed with BLOCK."""
    mgr = ChallengeManager(default_timeout=0.05)
    event = {
        "event_id": "evt_timeout_1",
        "session_id": "sess_t1",
        "agent_id": "agent_t1",
        "tool_name": "delete_all_files",
        "tool_server": "fs-mcp",
        "risk_score": 0.85,
    }

    chg = mgr.create_challenge(event, timeout_seconds=0.05, auto_dispatch=False)
    assert chg.status == ChallengeStatus.PENDING

    # Wait for resolution: operator does not resolve within 0.05s
    decision, resolved_chg = await mgr.wait_for_resolution(chg.challenge_id, timeout_seconds=0.05)

    assert decision == EventDecision.BLOCK
    assert resolved_chg.status == ChallengeStatus.EXPIRED
    assert resolved_chg.decision == EventDecision.BLOCK
    assert resolved_chg.resolved_by == "system:timeout"
    assert "deterministic fail-closed" in resolved_chg.resolution_reason


@pytest.mark.asyncio
async def test_post_timeout_approval_rejected():
    """An expired challenge cannot be retrospectively approved."""
    mgr = ChallengeManager(default_timeout=0.02)
    chg = mgr.create_challenge({"event_id": "e1"}, timeout_seconds=0.02, auto_dispatch=False)

    await asyncio.sleep(0.05)

    # Attempt to approve expired challenge
    with pytest.raises(ChallengeExpiredError):
        mgr.resolve_challenge(
            challenge_id=chg.challenge_id,
            action="approve",
            step_up_token=chg.step_up_token,
        )

    assert chg.status == ChallengeStatus.EXPIRED
    assert chg.decision == EventDecision.BLOCK


@pytest.mark.asyncio
async def test_concurrent_operator_approval_with_step_up_token():
    """Operator approval with valid step-up token unblocks waiting call with ALLOW."""
    mgr = ChallengeManager(default_timeout=5.0)
    event = {
        "event_id": "evt_appr",
        "session_id": "sess_appr",
        "agent_id": "agent_appr",
        "tool_name": "restart_service",
        "tool_server": "sys-mcp",
        "risk_score": 0.50,
    }

    chg = mgr.create_challenge(event, timeout_seconds=5.0, auto_dispatch=False)

    async def simulate_human_operator():
        await asyncio.sleep(0.05)
        mgr.resolve_challenge(
            challenge_id=chg.challenge_id,
            action="approve",
            operator_id="operator_carol",
            reason="Verified maintenance window",
            step_up_token=chg.step_up_token,
        )

    # Launch human operator in background
    asyncio.create_task(simulate_human_operator())

    # Wait for resolution
    decision, resolved_chg = await mgr.wait_for_resolution(chg.challenge_id)
    assert decision == EventDecision.ALLOW
    assert resolved_chg.status == ChallengeStatus.APPROVED
    assert resolved_chg.resolved_by == "operator_carol"
    assert resolved_chg.resolution_reason == "Verified maintenance window"


@pytest.mark.asyncio
async def test_concurrent_operator_rejection():
    """Operator rejection immediately resolves waiting call with BLOCK."""
    mgr = ChallengeManager(default_timeout=5.0)
    chg = mgr.create_challenge({"event_id": "e_rej"}, timeout_seconds=5.0, auto_dispatch=False)

    async def simulate_rejection():
        await asyncio.sleep(0.05)
        mgr.resolve_challenge(
            challenge_id=chg.challenge_id,
            action="reject",
            operator_id="operator_dave",
            reason="Suspicious destination",
        )

    asyncio.create_task(simulate_rejection())

    decision, resolved_chg = await mgr.wait_for_resolution(chg.challenge_id)
    assert decision == EventDecision.BLOCK
    assert resolved_chg.status == ChallengeStatus.REJECTED
    assert resolved_chg.resolved_by == "operator_dave"


def test_operator_approval_without_auth_raises_error():
    """Operator approval without step-up token or bearer credentials raises StepUpAuthError."""
    mgr = ChallengeManager(default_timeout=60.0)
    chg = mgr.create_challenge({"event_id": "e_unauth"}, auto_dispatch=False)

    with pytest.raises(StepUpAuthError) as exc_info:
        mgr.resolve_challenge(
            challenge_id=chg.challenge_id,
            action="approve",
            operator_id="attacker",
        )
    assert "requires" in str(exc_info.value).lower()


def test_operator_approval_replay_rejected():
    """Reusing the same step-up token on the same or another challenge is rejected."""
    mgr = ChallengeManager(default_timeout=60.0)
    chg = mgr.create_challenge({"event_id": "e_rep"}, auto_dispatch=False)

    # First resolution: approved
    mgr.resolve_challenge(
        challenge_id=chg.challenge_id,
        action="approve",
        step_up_token=chg.step_up_token,
    )
    assert chg.status == ChallengeStatus.APPROVED

    # Replay on another challenge with the same token
    chg2 = mgr.create_challenge({"event_id": "e_rep2"}, auto_dispatch=False)
    with pytest.raises(StepUpAuthError) as exc_info:
        mgr.resolve_challenge(
            challenge_id=chg2.challenge_id,
            action="approve",
            step_up_token=chg.step_up_token,  # Reused token
        )
    assert "replay" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()


def test_sweep_expired_marks_stale_challenges():
    """sweep_expired identifies and fails closed all timed-out challenges."""
    mgr = ChallengeManager(default_timeout=0.01)
    chg1 = mgr.create_challenge({"event_id": "e_sweep1"}, timeout_seconds=0.01, auto_dispatch=False)
    chg2 = mgr.create_challenge({"event_id": "e_sweep2"}, timeout_seconds=10.0, auto_dispatch=False)

    time.sleep(0.03)
    expired = mgr.sweep_expired()

    assert chg1.challenge_id in expired
    assert chg1.status == ChallengeStatus.EXPIRED
    assert chg1.decision == EventDecision.BLOCK

    assert chg2.challenge_id not in expired
    assert chg2.status == ChallengeStatus.PENDING


# ============================================================================
# 4. Proxy Engine & REST API End-to-End Integration Tests
# ============================================================================


@pytest.mark.asyncio
async def test_api_challenge_endpoints():
    """Verify /api/challenges listing and resolution with step-up auth."""
    orig_token = settings.admin_api_token
    settings.admin_api_token = "admin-test-secret-44"

    try:
        # Create a fresh engine instance for testing
        engine = CerberusProxyEngine()
        chg = engine.challenge_manager.create_challenge(
            {
                "event_id": "evt_api_1",
                "session_id": "sess_api",
                "agent_id": "agent_api",
                "tool_name": "terraform_apply",
                "tool_server": "iac-mcp",
                "risk_score": 0.65,
            },
            timeout_seconds=60.0,
            auto_dispatch=False,
        )
        engine.pending_challenges[chg.challenge_id] = chg.to_dict()

        with patch("cerberus.proxy.server.engine", engine):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # 1. GET /api/challenges lists the challenge
                res_list = await client.get("/api/challenges")
                assert res_list.status_code == 200
                items = res_list.json()
                assert any(c["challenge_id"] == chg.challenge_id for c in items)

                # 2. POST resolve without auth fails with 401
                res_unauth = await client.post(
                    f"/api/challenges/{chg.challenge_id}/resolve",
                    json={"action": "approve"},
                )
                assert res_unauth.status_code == 401

                # 3. POST resolve with invalid step-up token fails with 401
                res_bad = await client.post(
                    f"/api/challenges/{chg.challenge_id}/resolve",
                    json={"action": "approve", "step_up_token": "invalid.token.structure"},
                )
                assert res_bad.status_code == 401

                # 4. POST resolve with valid step-up token succeeds with 200
                res_ok = await client.post(
                    f"/api/challenges/{chg.challenge_id}/resolve",
                    json={
                        "action": "approve",
                        "step_up_token": chg.step_up_token,
                        "operator_id": "secops-dave",
                    },
                )
                assert res_ok.status_code == 200
                resp_data = res_ok.json()
                assert resp_data["status"] == "ok"
                assert resp_data["challenge"]["status"] == "approved"

                # 5. POST resolve with Bearer admin token succeeds for new challenge
                chg2 = engine.challenge_manager.create_challenge(
                    {"event_id": "evt_api_2"}, timeout_seconds=60.0, auto_dispatch=False
                )
                engine.pending_challenges[chg2.challenge_id] = chg2.to_dict()

                res_bearer = await client.post(
                    f"/api/challenges/{chg2.challenge_id}/resolve",
                    json={"action": "approve", "operator_id": "admin_user"},
                    headers={"Authorization": "Bearer admin-test-secret-44"},
                )
                assert res_bearer.status_code == 200
                assert res_bearer.json()["challenge"]["status"] == "approved"
    finally:
        settings.admin_api_token = orig_token


@pytest.mark.asyncio
async def test_engine_process_tool_call_challenge_flow():
    """Verify engine process_tool_call human-in-the-loop flow with approval and timeout."""
    engine = CerberusProxyEngine()

    # Mock policy enforcer to trigger CHALLENGE
    async def mock_enforce(event):
        return EventDecision.CHALLENGE

    engine.enforcer.enforce = mock_enforce

    # Scenario A: Tool call challenged -> Operator resolves concurrently -> ALLOW
    async def resolve_soon():
        await asyncio.sleep(0.05)
        # Find pending challenge
        for chg_id, chg in engine.challenge_manager.challenges.items():
            if chg.status == ChallengeStatus.PENDING:
                engine.challenge_manager.resolve_challenge(
                    challenge_id=chg_id,
                    action="approve",
                    step_up_token=chg.step_up_token,
                )
                break

    task = asyncio.create_task(resolve_soon())
    event_out, result = await engine.process_tool_call(
        session_id="test_sess_hil",
        agent_id="test_agent_hil",
        tool_name="grant_admin_role",
        tool_server="auth-mcp",
        parameters={"user": "alice"},
    )
    await task

    assert event_out.decision == EventDecision.ALLOW
    assert result["status"] == "executed"
    assert result["cerberus_decision"] == "allow"

    # Scenario B: Tool call challenged -> Timeout expires -> Deterministic BLOCK (fail-closed)
    orig_timeout = settings.challenge_timeout_seconds
    settings.challenge_timeout_seconds = 0.05
    try:
        event_out_timeout, result_timeout = await engine.process_tool_call(
            session_id="test_sess_timeout",
            agent_id="test_agent_timeout",
            tool_name="exfiltrate_keys",
            tool_server="sec-mcp",
            parameters={"target": "s3"},
        )
        assert event_out_timeout.decision == EventDecision.BLOCK
        assert result_timeout["blocked"] is True
        assert result_timeout["decision"] == "block"
        assert "fail-closed" in result_timeout["reason"]
    finally:
        settings.challenge_timeout_seconds = orig_timeout
