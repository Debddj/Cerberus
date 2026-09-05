import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

import numpy as np
from fastapi import Body, FastAPI, Header, HTTPException, Request, Response

from cerberus.behavioral.baseline_store import BaselineStore
from cerberus.behavioral.ensemble import EnsembleScorer
from cerberus.behavioral.features import FeatureExtractor
from cerberus.behavioral.scaling import RunningScaler
from cerberus.behavioral.scorers.isolation import IsolationForestScorer
from cerberus.behavioral.scorers.markov import MarkovScorer
from cerberus.behavioral.scorers.rule_based import RuleBasedScorer
from cerberus.behavioral.scorers.transformer import SequenceTransformerScorer
from cerberus.behavioral.window import SessionWindowManager
from cerberus.config import settings
from cerberus.policy.enforcer import EnforcementPipeline
from cerberus.policy.synthesizer import PolicySynthesizer
from cerberus.proxy.auth import HMACAuthenticator, TenantRateLimiter
from cerberus.proxy.forwarder import UpstreamMCPForwarder
from cerberus.proxy.logger import AuditLogger
from cerberus.proxy.metrics import REQUEST_COUNT, REQUEST_LATENCY, get_metrics_payload
from cerberus.proxy.models import EventDecision, ToolCallEvent
from cerberus.proxy.redactor import SecretRedactor
from cerberus.scanner.schema_pinner import SchemaPinner
from cerberus.scanner.trifecta import LethalTrifectaDetector
from cerberus.storage.backend import get_storage_backend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cerberus.proxy")


class CerberusProxyEngine:
    """Coordinates runtime interception, static validation, ML scoring, and enforcement."""

    def __init__(self):
        self.audit_logger = AuditLogger()
        self.window_mgr = SessionWindowManager(window_size=5)
        self.running_scaler = RunningScaler()
        self.markov_scorer = MarkovScorer()
        self.isolation_scorer = IsolationForestScorer()
        self.transformer_scorer = SequenceTransformerScorer()
        self.rule_scorer = RuleBasedScorer()
        self.ensemble_scorer = EnsembleScorer()
        self.schema_pinner = SchemaPinner(db_path=settings.pins_db_path)
        self.enforcer = EnforcementPipeline()
        self.forwarder = UpstreamMCPForwarder()
        self.baseline_store = BaselineStore(base_dir=settings.baselines_dir)
        self.policy_synthesizer = PolicySynthesizer()

        # Pillar 7 & 11: Multi-tenant auth, rate limiting, and storage backend
        self.authenticator = HMACAuthenticator(secret_key=settings.hmac_secret_key)
        self.rate_limiter = TenantRateLimiter(default_limit=settings.rate_limit_per_minute)
        self.storage = get_storage_backend(settings.redis_url)
        self.active_unverified_agents: set[str] = set()

        # Online learning buffers & state
        self.agent_allowed_events: dict[str, deque[ToolCallEvent]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self.if_buffer: list[list[float]] = []
        self.if_observation_count = 0
        self.transformer_training_sequences: dict[str, list[str]] = {}
        self._refit_task: asyncio.Task | None = None

        self.tool_counts: dict[str, dict[str, int]] = {}
        self.dest_counts: dict[str, dict[str, int]] = {}
        self.session_start_times: dict[str, float] = {}
        self.last_call_times: dict[str, float] = {}

    async def initialize(self):
        await self.schema_pinner.init_db()

    def _extract_destination(
        self, params: dict[str, Any], explicit_dest: str | None = None
    ) -> str | None:
        if explicit_dest:
            return explicit_dest
        for k, val in params.items():
            if k in ("destination_domain", "domain", "host") and isinstance(val, str):
                return val
            if isinstance(val, str) and val.startswith(("http://", "https://")):
                try:
                    return urlparse(val).netloc
                except Exception as e:
                    logger.debug(f"Failed to parse URL destination: {e}")
        return None

    async def _background_refit_loop(self):
        """Periodic background task that adapts models and snapshots baselines online."""
        while True:
            try:
                await asyncio.sleep(settings.online_learning_interval_seconds)
                await self.run_online_refit()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error in background online refit loop: {e}")

    async def run_online_refit(self, target_agent_id: str | None = None):
        """Runs online refit and creates versioned snapshots."""
        agents = [target_agent_id] if target_agent_id else list(self.agent_allowed_events.keys())
        for agent_id in agents:
            events = self.agent_allowed_events.get(agent_id)
            if not events or len(events) < 10:
                continue

            # Anti-poisoning stability gating
            valid, reason = self.baseline_store.validate_stability(
                agent_id, self.markov_scorer.transitions, max_divergence=0.5
            )
            if not valid:
                logger.warning(
                    f"Stability gate blocked snapshot promotion for {agent_id}: {reason}"
                )
                continue

            # Refit Isolation Forest on recent ALLOWed vectors
            if self.if_buffer and len(self.if_buffer) >= 20:
                self.isolation_scorer.fit(np.array(self.if_buffer[-settings.if_refit_interval :]))

            # Refit Sequence Transformer on observed session sequences
            sequences = list(self.transformer_training_sequences.values())
            if sequences:
                self.transformer_scorer.fit(sequences)

            # Persist versioned snapshot
            snapshot = self.baseline_store.create_snapshot(
                agent_id=agent_id,
                calls_count=len(events),
                transition_matrix=self.markov_scorer.transitions,
                if_model=self.isolation_scorer.model,
                transformer_model=self.transformer_scorer,
                scaling_params=self.running_scaler.stats,
            )
            logger.info(
                f"Online learning promoted snapshot {snapshot.snapshot_id} for agent '{agent_id}'"
            )

    async def process_tool_call(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_server: str,
        parameters: dict[str, Any],
        upstream_url: str | None = None,
        destination_domain: str | None = None,
        trust_level: str = "unverified",
        sequence_position: int | None = None,
    ) -> tuple[ToolCallEvent, dict[str, Any]]:
        now = time.time()
        param_str = json.dumps(parameters, sort_keys=True)
        param_bytes = len(param_str.encode("utf-8"))

        dest_domain = self._extract_destination(parameters, destination_domain)

        # 1. Secret Redaction
        redacted_params, redacted_fields = SecretRedactor.redact_dict(parameters)

        # Session timing
        if session_id not in self.session_start_times:
            self.session_start_times[session_id] = now
        session_duration_ms = (now - self.session_start_times[session_id]) * 1000.0

        time_since_prev_ms = None
        if session_id in self.last_call_times:
            time_since_prev_ms = (now - self.last_call_times[session_id]) * 1000.0
        self.last_call_times[session_id] = now

        prev_tools = self.window_mgr.get_recent_tools(session_id)
        seq_pos = sequence_position if sequence_position is not None else (len(prev_tools) + 1)
        all_session_tools = prev_tools + [tool_name]

        event = ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_server=tool_server,
            parameters=redacted_params,
            destination_domain=dest_domain,
            time_since_previous_ms=time_since_prev_ms,
            session_duration_ms=session_duration_ms,
            sequence_position=seq_pos,
            redacted_fields=redacted_fields,
            trust_level=trust_level,
        )

        # Record event in storage backend
        await self.storage.record_event(session_id, agent_id, event.model_dump(mode="json"))

        # 2. Static Checks: Lethal Trifecta
        is_trifecta, _breakdown = LethalTrifectaDetector.check_session_tools(all_session_tools)
        if is_trifecta and not getattr(settings, "trifecta_override", False):
            event.risk_score = 0.95
            event.risk_factors.append(
                "Lethal Trifecta: Session combines private data access, untrusted content exposure, and external egress"
            )

        # 3. Behavioral Features & Scaling
        agent_tools = self.tool_counts.setdefault(agent_id, {})
        agent_dests = self.dest_counts.setdefault(agent_id, {})
        tool_count = agent_tools.get(tool_name, 0)
        dest_count = agent_dests.get(dest_domain, 0) if dest_domain else 0

        # Running stats for z-score
        self.running_scaler.update("param_size", float(param_bytes))
        self.running_scaler.update("entropy", event.parameter_entropy)
        if time_since_prev_ms is not None:
            self.running_scaler.update("time_diff", float(time_since_prev_ms))
        self.running_scaler.update("duration", float(session_duration_ms))
        self.running_scaler.update("seq_pos", float(seq_pos))

        z_stats = {
            k: self.running_scaler.get_mean_std(k)
            for k in ["param_size", "entropy", "response_size", "time_diff", "duration", "seq_pos"]
        }

        markov_f, if_f, rule_f = FeatureExtractor.extract_all(
            event=event,
            prev_tools=prev_tools,
            tool_seen_count=tool_count,
            dest_seen_count=dest_count,
            z_stats=z_stats,
        )

        # 4. Cost-Aware Tiered Cascading Behavioral Pipeline (Pillar 6)
        # Tier 1: Fast Heuristic Rule Scorer + Markov (<1ms budget)
        r_score, r_factors = self.rule_scorer.score(rule_f)
        m_score, m_factors = self.markov_scorer.score(markov_f)
        tier1_score = 0.5 * r_score + 0.5 * m_score
        tier1_factors = r_factors + m_factors

        # Decisive early exit check
        if r_score >= 0.75 or tier1_score >= 0.90:
            ens_score = max(r_score, tier1_score)
            ens_factors = tier1_factors
        else:
            # Cheap Escalation Trigger: high z-score or moderate tier 1 score
            cheap_escalate = (tier1_score >= 0.20) or any(
                abs(getattr(if_f, attr, 0.0)) >= 3.0
                for attr in [
                    "param_size_bytes_z",
                    "param_entropy_z",
                    "time_since_previous_ms_z",
                    "session_duration_ms_z",
                    "sequence_position_z",
                ]
            )

            if not cheap_escalate:
                # Fast allow under Tier 1 budget
                ens_score = tier1_score
                ens_factors = tier1_factors
            else:
                # Tier 2: Isolation Forest Scorer
                i_score, i_factors = self.isolation_scorer.score(if_f)
                tier2_score = 0.30 * r_score + 0.30 * m_score + 0.40 * i_score
                if i_score >= 0.80:
                    tier2_score = max(tier2_score, 0.80)
                tier2_factors = tier1_factors + i_factors

                # Tier 2 Early Exit: Decisive Allow (<0.35) or Decisive Block (>=0.70)
                if tier2_score < 0.35 or tier2_score >= 0.70:
                    ens_score = tier2_score
                    ens_factors = tier2_factors
                else:
                    # Tier 3: Ambiguous Band (0.35 <= score < 0.70) -> Sequence Transformer
                    t_score, t_factors = self.transformer_scorer.score(all_session_tools)
                    ens_score, ens_factors = self.ensemble_scorer.combine(
                        rule_score=r_score,
                        markov_score=m_score,
                        isolation_score=i_score,
                        transformer_score=t_score,
                        rule_factors=r_factors,
                        markov_factors=m_factors,
                        isolation_factors=i_factors,
                        transformer_factors=t_factors,
                    )

        if event.risk_score is None or ens_score > event.risk_score:
            event.risk_score = ens_score
        event.risk_factors.extend(ens_factors)
        event.risk_factors = list(dict.fromkeys(event.risk_factors))

        # 5. Policy Enforcement
        decision = await self.enforcer.enforce(event)
        event.decision = decision

        # 6. Audit Logging & State Update
        await self.audit_logger.log_event(event)

        # Update baseline counts if safe (stability gating)
        if decision in (EventDecision.ALLOW, EventDecision.FLAG):
            self.window_mgr.record_tool(session_id, tool_name)
            agent_tools[tool_name] = tool_count + 1
            if dest_domain:
                agent_dests[dest_domain] = dest_count + 1
            if prev_tools:
                self.markov_scorer.update(prev_tools[-1], tool_name)

            if decision == EventDecision.ALLOW:
                self.agent_allowed_events[agent_id].append(event)
                if_vec = [
                    if_f.param_size_bytes_z,
                    if_f.param_entropy_z,
                    if_f.response_size_bytes_z,
                    if_f.time_since_previous_ms_z,
                    if_f.session_duration_ms_z,
                    if_f.sequence_position_z,
                    if_f.destination_novelty,
                    if_f.tool_novelty,
                ]
                self.if_buffer.append(if_vec)
                self.if_observation_count += 1
                self.transformer_training_sequences.setdefault(session_id, []).append(tool_name)

                if (
                    not self.isolation_scorer.is_fitted
                    and self.if_observation_count >= settings.warm_threshold_calls
                ):
                    self.isolation_scorer.fit(np.array(self.if_buffer))

                if (
                    not self.transformer_scorer.is_fitted
                    and self.if_observation_count >= settings.warm_threshold_calls
                ):
                    self.transformer_scorer.fit(list(self.transformer_training_sequences.values()))

        elif decision in (EventDecision.BLOCK, EventDecision.QUARANTINE):
            # Closed-loop policy synthesis: generate candidate Rego rule
            try:
                self.policy_synthesizer.synthesize_for_blocked(event)
            except Exception as e:
                logger.warning(f"Failed to auto-synthesize policy: {e}")

        # 7. Execution or Blocking
        if decision in (EventDecision.BLOCK, EventDecision.QUARANTINE):
            return event, {
                "blocked": True,
                "decision": decision.value,
                "reason": event.decision_reason,
                "risk_score": event.risk_score,
                "factors": event.risk_factors,
            }

        # Forward if upstream configured
        if upstream_url:
            upstream_res = await self.forwarder.forward_call(
                server_url=upstream_url,
                method="tools/call",
                params={"name": tool_name, "arguments": parameters},
            )
            return event, upstream_res

        return event, {
            "status": "executed",
            "cerberus_decision": decision.value,
            "tool_name": tool_name,
            "result": f"Executed tool '{tool_name}' successfully",
        }

    async def close(self):
        if self._refit_task:
            self._refit_task.cancel()
        if hasattr(self.enforcer, "close"):
            await self.enforcer.close()
        elif hasattr(self.enforcer, "opa_client") and hasattr(self.enforcer.opa_client, "close"):
            await self.enforcer.opa_client.close()
        if hasattr(self.forwarder, "close"):
            await self.forwarder.close()
        if hasattr(self.schema_pinner, "close"):
            await self.schema_pinner.close()
        if hasattr(self.storage, "close"):
            await self.storage.close()


engine = CerberusProxyEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await engine.initialize()
    engine._refit_task = asyncio.create_task(engine._background_refit_loop())
    try:
        yield
    finally:
        await engine.close()


app = FastAPI(
    title="Cerberus MCP Firewall",
    description="A runtime behavioral firewall for MCP-based AI agents",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/healthz")
async def health_check():
    storage_health = await engine.storage.health_check()
    return {
        "status": "healthy",
        "mode": settings.mode,
        "opa_url": settings.opa_url,
        "fail_closed": settings.fail_closed,
        "active_unverified_agents": len(engine.active_unverified_agents),
        "unverified_agents": list(engine.active_unverified_agents),
        "storage": storage_health,
    }


@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics_payload(), media_type="text/plain; version=0.0.4")


# Policy Simulation and Closed-Loop Synthesis Endpoints
@app.post("/policy/simulate")
async def simulate_policy(payload: dict[str, Any] = Body(...)):  # noqa: B008
    """Simulate tool call against multi-package OPA policies."""
    event_data = payload.get("event", {})
    static_scan = payload.get("static_scan")
    overrides = payload.get("overrides")
    event = ToolCallEvent(**event_data)
    opa_client = getattr(engine.enforcer, "opa_client", None)
    if not opa_client:
        from cerberus.policy.opa_client import OPAClient

        opa_client = OPAClient()
    return await opa_client.simulate(event, static_scan=static_scan, policy_overrides=overrides)


@app.post("/baselines/{agent_id}/promote")
async def promote_agent_baseline(agent_id: str):
    """Manually trigger online refit and snapshot promotion for an agent."""
    await engine.run_online_refit(target_agent_id=agent_id)
    baseline = engine.baseline_store.get_baseline(agent_id)
    return {
        "agent_id": agent_id,
        "active_snapshot_id": baseline.active_snapshot_id,
        "snapshots_count": len(baseline.snapshots),
    }


@app.get("/admin/policies/pending")
async def list_pending_policies():
    """List pending auto-synthesized Rego policies."""
    return engine.policy_synthesizer.list_pending_policies()


@app.post("/admin/policies/{policy_id}/approve")
async def approve_policy(policy_id: str):
    """Approve candidate synthesized policy."""
    ok = engine.policy_synthesizer.approve_policy(policy_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Policy not found or failed to approve")
    return {"status": "approved", "policy_id": policy_id}


@app.post("/admin/policies/{policy_id}/reject")
async def reject_policy(policy_id: str):
    """Reject candidate synthesized policy."""
    ok = engine.policy_synthesizer.reject_policy(policy_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Policy not found or failed to reject")
    return {"status": "rejected", "policy_id": policy_id}


@app.post("/")
@app.post("/mcp")
async def mcp_proxy_gateway(
    request: Request,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    x_upstream_url: str | None = Header(default=None, alias="X-Upstream-URL"),
    x_cerberus_signature: str | None = Header(default=None, alias="X-Cerberus-Signature"),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    start_time = time.perf_counter()
    body = await request.json()
    req_id = body.get("id", 1)
    method = body.get("method", "tools/call")
    params = body.get("params", {})

    # Extract signature token
    raw_token = x_cerberus_signature or authorization
    if raw_token and raw_token.startswith("Bearer "):
        raw_token = raw_token.split(" ", 1)[1]

    # Verify HMAC token
    verified_agent = None
    if raw_token:
        is_valid, token_agent, _ = engine.authenticator.verify_token(raw_token)
        if is_valid:
            verified_agent = token_agent

    if settings.require_signed_identity:
        if not verified_agent:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32001,
                    "message": "Unauthorized: valid HMAC identity token required",
                },
            }
        trust_level = "verified"
        agent_id = verified_agent
        session_id = x_session_id or f"session-{uuid.uuid4().hex[:8]}"
    else:
        # Permissive mode
        if verified_agent:
            trust_level = "verified"
            agent_id = verified_agent
        else:
            trust_level = "unverified"
            # Bug 19: generate random identifiers if missing or generic
            if x_agent_id and x_agent_id != "default-agent":
                agent_id = x_agent_id
            else:
                agent_id = f"agent-unverified-{uuid.uuid4().hex[:8]}"

        if x_session_id and x_session_id != "default-session":
            session_id = x_session_id
        else:
            session_id = f"session-{uuid.uuid4().hex[:8]}"

    if trust_level == "unverified":
        engine.active_unverified_agents.add(agent_id)
    else:
        engine.active_unverified_agents.discard(agent_id)

    # Per-tenant rate limiting
    rate_ok, _, _reset_secs = engine.rate_limiter.check_rate_limit(agent_id)
    if not rate_ok:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32029,
                "message": f"Rate limit exceeded for agent '{agent_id}' ({settings.rate_limit_per_minute}/min)",
            },
        }

    if method == "tools/list":
        duration = time.perf_counter() - start_time
        REQUEST_LATENCY.observe(duration)
        REQUEST_COUNT.labels(tool_name="tools/list", decision="allow").inc()
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read file from disk",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                        },
                    },
                    {
                        "name": "query_db",
                        "description": "Query database",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                        },
                    },
                    {
                        "name": "http_post",
                        "description": "Send external HTTP POST payload",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"url": {"type": "string"}, "data": {"type": "string"}},
                        },
                    },
                ]
            },
        }

    # Default to tools/call processing
    tool_name = params.get("name", "unknown_tool")
    arguments = params.get("arguments", params)
    tool_server = params.get("server", "upstream-server")

    event, outcome = await engine.process_tool_call(
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        tool_server=tool_server,
        parameters=arguments,
        upstream_url=x_upstream_url,
        trust_level=trust_level,
    )

    duration = time.perf_counter() - start_time
    REQUEST_LATENCY.observe(duration)
    decision_label = event.decision.value if event.decision else "allow"
    REQUEST_COUNT.labels(tool_name=tool_name, decision=decision_label).inc()

    if outcome.get("blocked"):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32003,
                "message": f"Cerberus firewall blocked tool call: {outcome.get('reason')}",
                "data": outcome,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": outcome,
    }
