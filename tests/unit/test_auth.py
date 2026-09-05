from cerberus.proxy.auth import HMACAuthenticator, TenantRateLimiter


def test_hmac_authenticator_issue_and_verify():
    auth = HMACAuthenticator(secret_key="test-secret-key-12345678901234567890")
    token = auth.issue_token(agent_id="coding-agent-01", ttl_seconds=3600)
    assert token is not None

    # Valid verification
    is_valid, agent_id, reason = auth.verify_token(token)
    assert is_valid is True
    assert agent_id == "coding-agent-01"
    assert "verified" in reason.lower()

    # Tampered signature
    tampered = token[:-4] + "AAAA"
    is_valid_t, _, reason_t = auth.verify_token(tampered)
    assert is_valid_t is False
    assert "invalid" in reason_t.lower()

    # Expired token
    expired_token = auth.issue_token(agent_id="expired-agent", ttl_seconds=-10)
    is_valid_e, _, reason_e = auth.verify_token(expired_token)
    assert is_valid_e is False
    assert "expired" in reason_e.lower()


def test_tenant_rate_limiter():
    limiter = TenantRateLimiter(default_limit=3)

    # First 3 calls allowed
    assert limiter.check_rate_limit("agent-A")[0] is True
    assert limiter.check_rate_limit("agent-A")[0] is True
    assert limiter.check_rate_limit("agent-A")[0] is True

    # 4th call blocked
    allowed, remaining, reset_sec = limiter.check_rate_limit("agent-A")
    assert allowed is False
    assert remaining == 0
    assert reset_sec > 0

    # Independent quota for agent-B
    assert limiter.check_rate_limit("agent-B")[0] is True
