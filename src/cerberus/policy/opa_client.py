import logging
import time

import httpx

from cerberus.config import settings
from cerberus.proxy.models import EventDecision, ToolCallEvent

logger = logging.getLogger("cerberus.opa")


class OPAClient:
    """Queries Open Policy Agent sidecar with built-in Fail-Closed outage handling and circuit breaker."""

    def __init__(self, opa_url: str | None = None, timeout: float = 0.5):
        self.opa_url = opa_url or settings.opa_url
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=self.timeout)
        self._circuit_open = False
        self._last_failure_time = 0.0
        self._retry_interval = 10.0

    async def evaluate(self, event: ToolCallEvent) -> tuple[EventDecision, str]:
        now = time.time()
        if self._circuit_open and (now - self._last_failure_time < self._retry_interval):
            return self._fail_closed_verdict(event, "OPA Circuit Open")

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
            self._circuit_open = False
            data = resp.json()
            decision_str = data.get("result", "allow")
            return EventDecision(decision_str), f"OPA Policy Decision: {decision_str}"

        except Exception as e:
            if not self._circuit_open:
                logger.warning(f"OPA unreachable, opening circuit breaker: {e}")
            self._circuit_open = True
            self._last_failure_time = now
            return self._fail_closed_verdict(event, "OPA Outage")

    def _fail_closed_verdict(
        self, event: ToolCallEvent, reason_prefix: str
    ) -> tuple[EventDecision, str]:
        score = event.risk_score or 0.0
        if settings.fail_closed:
            if score >= settings.risk_quarantine_threshold:
                return (
                    EventDecision.QUARANTINE,
                    f"{reason_prefix}: Fail-Closed quarantined critical-risk call",
                )
            if score >= settings.risk_block_threshold:
                return (
                    EventDecision.BLOCK,
                    f"{reason_prefix}: Fail-Closed blocked elevated-risk call",
                )
            if score >= settings.risk_flag_threshold:
                return EventDecision.FLAG, f"{reason_prefix}: Degraded flag for moderate-risk call"
            return EventDecision.ALLOW, f"{reason_prefix}: Degraded allow for low-risk call"
        return EventDecision.ALLOW, f"{reason_prefix}: Fail-Open mode"
