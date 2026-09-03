import pytest
import asyncio
from cerberus.policy.opa_client import OPAClient
from cerberus.proxy.models import ToolCallEvent, EventDecision

def test_fail_closed_on_unreachable_opa():
    async def _run():
        client = OPAClient(opa_url="http://invalid-host:9999", timeout=0.1)
        high_risk_event = ToolCallEvent(
            session_id="s1",
            agent_id="a1",
            tool_name="http_post",
            tool_server="srv",
            risk_score=0.85
        )
        decision, reason = await client.evaluate(high_risk_event)
        assert decision == EventDecision.BLOCK
        assert "Fail-Closed" in reason

    asyncio.run(_run())
