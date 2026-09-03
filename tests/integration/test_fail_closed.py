import pytest
import asyncio
from cerberus.policy.opa_client import OPAClient
from cerberus.proxy.models import ToolCallEvent, EventDecision

def test_fail_closed_behavior():
    async def _run():
        client = OPAClient(opa_url="http://localhost:59999", timeout=0.05)
        low_event = ToolCallEvent(session_id="s1", agent_id="a1", tool_name="read", tool_server="srv", risk_score=0.2)
        dec_low, _ = await client.evaluate(low_event)
        assert dec_low == EventDecision.ALLOW

        high_event = ToolCallEvent(session_id="s1", agent_id="a1", tool_name="post", tool_server="srv", risk_score=0.8)
        dec_high, _ = await client.evaluate(high_event)
        assert dec_high == EventDecision.BLOCK
    asyncio.run(_run())
