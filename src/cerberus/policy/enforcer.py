from cerberus.policy.opa_client import OPAClient
from cerberus.proxy.models import EventDecision, ToolCallEvent


class EnforcementPipeline:
    """Coordinates static scanner, ML engine, and OPA policy evaluation."""

    def __init__(self, opa_client: OPAClient | None = None):
        self.opa_client = opa_client or OPAClient()

    async def enforce(self, event: ToolCallEvent) -> EventDecision:
        # High risk threshold directly triggers quarantine
        if (event.risk_score or 0.0) >= 0.90:
            event.decision = EventDecision.QUARANTINE
            event.decision_reason = "Quarantine: Critical behavioral drift anomaly detected"
            return EventDecision.QUARANTINE

        decision, reason = await self.opa_client.evaluate(event)
        event.decision = decision
        event.decision_reason = reason
        return decision
