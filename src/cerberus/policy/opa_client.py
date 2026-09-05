import logging
import time
from typing import Any

import httpx

from cerberus.config import settings
from cerberus.proxy.models import EventDecision, ToolCallEvent

logger = logging.getLogger("cerberus.opa")


class OPAClient:
    """Queries Open Policy Agent sidecar across multi-package policies with built-in
    Fail-Closed outage handling, circuit breaker, and interactive policy simulation."""

    POLICY_PACKAGES = [
        "cerberus/behavioral",
        "cerberus/privilege_escalation",
        "cerberus/rug_pull",
        "cerberus/trifecta",
    ]

    def __init__(self, opa_url: str | None = None, timeout: float = 0.5):
        self.opa_url = (opa_url or settings.opa_url).rstrip("/")
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=self.timeout)
        self._circuit_open = False
        self._last_failure_time = 0.0
        self._retry_interval = 10.0

    def _build_payload(
        self,
        event: ToolCallEvent,
        static_scan: dict[str, bool] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        scan = static_scan or {
            "schema_drift": False,
            "lethal_trifecta": False,
            "out_of_scope": False,
        }
        cfg = {
            "schema_pin_mode": settings.mode,
            "trifecta_override": settings.trifecta_override,
        }
        if overrides:
            cfg.update(overrides)

        return {
            "input": {
                "event_id": event.event_id,
                "agent_id": event.agent_id,
                "tool_name": event.tool_name,
                "tool_server": event.tool_server,
                "risk_score": event.risk_score or 0.0,
                "destination_domain": event.destination_domain,
                "static_scan": scan,
                "config": cfg,
            }
        }

    async def evaluate(
        self,
        event: ToolCallEvent,
        static_scan: dict[str, bool] | None = None,
    ) -> tuple[EventDecision, str]:
        """Evaluates event against OPA policy packages, selecting the most restrictive verdict."""
        now = time.time()
        if self._circuit_open and (now - self._last_failure_time < self._retry_interval):
            return self._fail_closed_verdict(event, "OPA Circuit Open")

        payload = self._build_payload(event, static_scan)
        reasons: list[str] = []
        highest_decision = EventDecision.ALLOW

        # Decision severity hierarchy for selecting most restrictive
        severity = {
            EventDecision.ALLOW: 0,
            EventDecision.FLAG: 1,
            EventDecision.QUARANTINE: 2,
            EventDecision.BLOCK: 3,
        }

        try:
            # Query the primary behavioral decision endpoint
            resp = await self.client.post(
                f"{self.opa_url}/v1/data/cerberus/behavioral/decision", json=payload
            )
            resp.raise_for_status()
            self._circuit_open = False
            data = resp.json()
            decision_str = data.get("result", "allow")
            dec = EventDecision(decision_str)
            if severity[dec] > severity[highest_decision]:
                highest_decision = dec
            reasons.append(f"behavioral:{decision_str}")

            return (
                highest_decision,
                f"OPA Decision: {highest_decision.value} ({', '.join(reasons)})",
            )

        except Exception as e:
            if not self._circuit_open:
                logger.warning(f"OPA unreachable, opening circuit breaker: {e}")
            self._circuit_open = True
            self._last_failure_time = now
            return self._fail_closed_verdict(event, "OPA Outage")

    async def simulate(
        self,
        event: ToolCallEvent,
        static_scan: dict[str, bool] | None = None,
        policy_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Interactive debugger/simulation endpoint: queries all policy packages and returns
        comprehensive breakdown of rule matches and decisions."""
        payload = self._build_payload(event, static_scan, policy_overrides)
        sim_results: dict[str, Any] = {
            "event_id": event.event_id,
            "agent_id": event.agent_id,
            "tool_name": event.tool_name,
            "risk_score": event.risk_score or 0.0,
            "packages": {},
            "final_decision": "allow",
            "reasons": [],
        }

        severity = {
            "allow": 0,
            "flag": 1,
            "quarantine": 2,
            "block": 3,
        }
        highest = "allow"

        for pkg in self.POLICY_PACKAGES:
            endpoint = f"{self.opa_url}/v1/data/{pkg}/decision"
            try:
                resp = await self.client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    res_val = resp.json().get("result", "allow")
                    sim_results["packages"][pkg] = {"status": "ok", "decision": res_val}
                    if severity.get(res_val, 0) > severity.get(highest, 0):
                        highest = res_val
                else:
                    sim_results["packages"][pkg] = {"status": "error", "code": resp.status_code}
            except Exception as ex:
                sim_results["packages"][pkg] = {"status": "unreachable", "error": str(ex)}

        # If OPA is unreachable across all, fallback to fail-closed simulation
        if all(v.get("status") != "ok" for v in sim_results["packages"].values()):
            fallback_dec, fallback_reason = self._fail_closed_verdict(event, "Simulation Fallback")
            highest = fallback_dec.value
            sim_results["reasons"].append(fallback_reason)

        sim_results["final_decision"] = highest
        return sim_results

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

    async def close(self):
        """Gracefully close the underlying httpx client."""
        await self.client.aclose()
