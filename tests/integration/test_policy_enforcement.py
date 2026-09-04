import asyncio

from cerberus.policy.enforcer import EnforcementPipeline
from cerberus.proxy.models import EventDecision, ToolCallEvent


def test_enforcement_pipeline():
    async def _run():
        pipeline = EnforcementPipeline()
        event = ToolCallEvent(
            session_id="s1",
            agent_id="a1",
            tool_name="http_post",
            tool_server="webhook-server",
            risk_score=0.95,
        )
        dec = await pipeline.enforce(event)
        assert dec == EventDecision.QUARANTINE

    asyncio.run(_run())
