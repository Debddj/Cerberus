import logging

import httpx

from cerberus.config import settings
from cerberus.proxy.models import EventDecision, ToolCallEvent

logger = logging.getLogger("cerberus.opa")


class OPAClient:
    """Queries Open Policy Agent sidecar with built-in Fail-Closed outage handling."""

    def __init__(self, opa_url: str | None = None, timeout: float = 2.0):
        self.opa_url = opa_url or settings.opa_url
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=self.timeout)

    async def evaluate(self, event: ToolCallEvent) -> tuple[EventDecision, str]:
        payload = {
            "input": {
                "event_id": event.event_id,
                "agent_id": event.agent_id,
                "tool_name": event.tool_name,
                "tool_server": event.tool_server,
                "risk_score": event.risk_score or 0.0,
                "destination_domain": event.destination_domain,
                "static_scan": {
                    "schema_drift": False,
                    "lethal_trifecta": False,
                    "out_of_scope": False,
                },
                "config": {"schema_pin_mode": settings.mode, "trifecta_override": False},
            }
        }

        try:
            resp = await self.client.post(
                f"{self.opa_url}/cerberus/behavioral/decision", json=payload
            )
            resp.raise_for_status()
            data = resp.json()
            decision_str = data.get("result", "allow")
            return EventDecision(decision_str), f"OPA Policy Decision: {decision_str}"

        except Exception as e:
            logger.error(f"OPA unreachable or timeout: {e}")
            if settings.fail_closed:
                # Fail-Closed default for elevated risk
                if (event.risk_score or 0.0) >= 0.70:
                    return EventDecision.BLOCK, "OPA Outage: Fail-Closed blocked elevated-risk call"
                return EventDecision.ALLOW, "OPA Outage: Degraded allow for low-risk call"
            return EventDecision.ALLOW, "OPA Outage: Fail-Open mode"
