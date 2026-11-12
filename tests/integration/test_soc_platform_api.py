import os

import pytest
from httpx import ASGITransport, AsyncClient

from cerberus.proxy.server import app


@pytest.mark.asyncio
async def test_soc_auth_and_public_spa_routes():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for route in ["/", "/features", "/architecture", "/threat-lab", "/docs", "/login"]:
            res = await client.get(route)
            assert res.status_code == 200
            assert "<!doctype html>" in res.text.lower()

        logo_res = await client.get("/cerberus-logo.svg")
        assert logo_res.status_code == 200
        assert "<svg" in logo_res.text

        bad_login = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-password"},
        )
        assert bad_login.status_code == 401

        ok_login = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "cerberus-soc"},
        )
        assert ok_login.status_code == 200
        login_data = ok_login.json()
        assert login_data["authenticated"] is True
        token = login_data["token"]

        sess_res = await client.get(
            "/api/auth/session",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert sess_res.status_code == 200
        assert sess_res.json()["authenticated"] is True


@pytest.mark.asyncio
async def test_soc_agents_behavior_incidents_testing_and_analytics():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register an agent
        reg = await client.post(
            "/api/agents",
            json={
                "agent_id": "soc-test-agent",
                "agent_type": "Coding",
                "mcp_servers": ["file-server"],
                "authorized_tools": ["read_file"],
                "enforce_scope": True,
                "issue_token": True,
            },
        )
        assert reg.status_code == 200
        reg_data = reg.json()
        assert reg_data["agent_id"] == "soc-test-agent"
        assert reg_data["token"]

        # 2. Suspend & enforce block on /mcp
        susp = await client.post("/api/agents/soc-test-agent/suspend")
        assert susp.status_code == 200
        assert susp.json()["status"] == "suspended"

        blocked_call = await client.post(
            "/mcp",
            headers={"X-Agent-ID": "soc-test-agent"},
            json={
                "jsonrpc": "2.0",
                "id": 501,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "README.md"}},
            },
        )
        assert "error" in blocked_call.json()

        act = await client.post("/api/agents/soc-test-agent/activate")
        assert act.status_code == 200

        # 3. Run live security testing scenario
        test_run = await client.post(
            "/api/testing/run",
            json={"scenario_id": "prompt_injection"},
        )
        assert test_run.status_code == 200
        run_data = test_run.json()
        assert run_data["execution_mode"] == "live_backend_engine"
        assert run_data["peak_risk_score"] >= 0.90
        assert run_data["final_decision"] in ("block", "quarantine")

        # 4. Behavior endpoint returns real ensemble weights
        beh = await client.get("/api/behavior")
        assert beh.status_code == 200
        beh_data = beh.json()
        assert "ensemble_weights" in beh_data
        assert "markov" in beh_data
        assert "rule_engine" in beh_data

        # 5. Incidents endpoint captures the blocked scenario
        inc = await client.get("/api/incidents")
        assert inc.status_code == 200
        assert isinstance(inc.json(), list)
        assert len(inc.json()) >= 1

        # 6. Analytics & System Config
        ana = await client.get("/api/analytics")
        assert ana.status_code == 200
        ana_data = ana.json()
        assert ana_data["live_telemetry"]["total_calls"] >= 1
        assert ana_data["evaluation_benchmark"] is not None

        cfg = await client.get("/api/system/config")
        assert cfg.status_code == 200
        assert "risk_block_threshold" in cfg.json()

        # 7. Audit status & clean up registered agent
        aud_status = await client.get("/api/audit/status")
        assert aud_status.status_code == 200
        assert "chain_head_hash" in aud_status.json()

        del_res = await client.delete("/api/agents/soc-test-agent")
        assert del_res.status_code == 200


@pytest.mark.asyncio
async def test_soc_policy_create_toggle_and_cleanup():
    transport = ASGITransport(app=app)
    custom_path = os.path.join("policies", "custom", "test_soc_policy.rego")
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post(
                "/api/policies",
                json={
                    "name": "test_soc_policy.rego",
                    "code": "package cerberus.custom.test_soc\n\ndefault allow := true\n",
                    "push_to_opa": False,
                },
            )
            assert created.status_code == 200
            assert created.json()["saved"] is True

            toggled = await client.post("/api/policies/test_soc_policy.rego/toggle")
            assert toggled.status_code == 200
            assert toggled.json()["enabled"] is False
    finally:
        if os.path.exists(custom_path):
            os.remove(custom_path)
        custom_dir = os.path.dirname(custom_path)
        if os.path.isdir(custom_dir) and not os.listdir(custom_dir):
            os.rmdir(custom_dir)
