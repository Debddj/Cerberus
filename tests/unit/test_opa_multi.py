from unittest.mock import AsyncMock, MagicMock

import pytest

from cerberus.policy.opa_client import OPAClient
from cerberus.proxy.models import EventDecision, ToolCallEvent


@pytest.mark.asyncio
async def test_opa_client_simulate_fallback():
    client = OPAClient(opa_url="http://127.0.0.1:9999", timeout=0.1)
    event = ToolCallEvent(
        session_id="s1",
        agent_id="a1",
        tool_name="cmd_run",
        tool_server="sys",
        risk_score=0.85,
    )

    sim = await client.simulate(event)
    assert sim["tool_name"] == "cmd_run"
    assert sim["risk_score"] == 0.85
    # Should fallback to fail-closed quarantine or block for high risk
    assert sim["final_decision"] in ["block", "quarantine"]
    assert "Simulation Fallback" in sim["reasons"][0]

    await client.close()


@pytest.mark.asyncio
async def test_opa_client_evaluate_mock_success():
    client = OPAClient(opa_url="http://mock-opa", timeout=0.1)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": "block"}
    mock_resp.raise_for_status = MagicMock()

    client.client.post = AsyncMock(return_value=mock_resp)

    event = ToolCallEvent(
        session_id="s2",
        agent_id="a2",
        tool_name="drop_db",
        tool_server="db",
        risk_score=0.9,
    )

    decision, reason = await client.evaluate(event)
    assert decision == EventDecision.BLOCK
    assert "OPA Decision: block" in reason

    await client.close()
