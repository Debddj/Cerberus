import pytest
from httpx import ASGITransport, AsyncClient

from cerberus.config import settings
from cerberus.proxy.server import app


@pytest.mark.asyncio
async def test_admin_api_auth_enforcement():
    """Verify that admin and promotion endpoints require a valid X-Admin-Token (BUG-B7 fix)."""
    orig_token = settings.admin_api_token
    settings.admin_api_token = "secure-secops-token-7788"

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Unauthenticated request to /admin/policies/pending fails with 401
            res_unauth = await client.get("/admin/policies/pending")
            assert res_unauth.status_code == 401
            assert "Unauthorized" in res_unauth.json().get("detail", "")

            # 2. Request with invalid token fails with 401
            res_bad = await client.get(
                "/admin/policies/pending", headers={"X-Admin-Token": "wrong-token"}
            )
            assert res_bad.status_code == 401

            # 3. Request with valid X-Admin-Token succeeds with 200
            res_ok = await client.get(
                "/admin/policies/pending",
                headers={"X-Admin-Token": "secure-secops-token-7788"},
            )
            assert res_ok.status_code == 200
            assert isinstance(res_ok.json(), list)

            # 4. Bearer authorization header works identically
            res_bearer = await client.get(
                "/admin/policies/pending",
                headers={"Authorization": "Bearer secure-secops-token-7788"},
            )
            assert res_bearer.status_code == 200

            # 5. Baseline promote endpoint (/baselines/{agent_id}/promote) enforces admin auth
            res_prom_unauth = await client.post("/baselines/agent-sec/promote")
            assert res_prom_unauth.status_code == 401

            res_prom_ok = await client.post(
                "/baselines/agent-sec/promote",
                headers={"X-Admin-Token": "secure-secops-token-7788"},
            )
            assert res_prom_ok.status_code == 200
            assert res_prom_ok.json()["agent_id"] == "agent-sec"

            # 6. Baseline refit alias endpoint (/api/baselines/{agent_id}/refit) enforces admin auth
            res_refit_unauth = await client.post("/api/baselines/agent-sec/refit")
            assert res_refit_unauth.status_code == 401

            res_refit_ok = await client.post(
                "/api/baselines/agent-sec/refit",
                headers={"X-Admin-Token": "secure-secops-token-7788"},
            )
            assert res_refit_ok.status_code == 200

            # 7. Policy approve alias endpoint (/api/policies/{id}/approve) enforces admin auth
            res_appr_unauth = await client.post("/api/policies/pol-nonexistent/approve")
            assert res_appr_unauth.status_code == 401
    finally:
        settings.admin_api_token = orig_token


@pytest.mark.asyncio
async def test_admin_api_open_in_dev_when_unconfigured():
    """Verify that admin endpoints remain accessible in dev when no token is configured."""
    orig_token = settings.admin_api_token
    settings.admin_api_token = ""

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/admin/policies/pending")
            assert res.status_code == 200
            assert isinstance(res.json(), list)
    finally:
        settings.admin_api_token = orig_token
