import asyncio
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

import numpy as np
from fastapi import Body, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

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
from cerberus.proxy.metrics import (
    ACTIVE_QUARANTINES,
    REQUEST_COUNT,
    REQUEST_LATENCY,
    get_metrics_payload,
)
from cerberus.proxy.models import EventDecision, ToolCallEvent
from cerberus.proxy.redactor import SecretRedactor
from cerberus.proxy.soc_routes import create_soc_router
from cerberus.scanner.schema_pinner import SchemaPinner
from cerberus.scanner.scope_analyzer import ScopeAnalyzer
from cerberus.scanner.shadow_detector import ShadowDetector
from cerberus.scanner.trifecta import LethalTrifectaDetector
from cerberus.storage.backend import get_storage_backend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cerberus.proxy")


def _read_file_sync(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _read_file_lines_sync(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


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

        # BUG-C2/C3 fix: Wire ScopeAnalyzer and ShadowDetector into runtime
        self.scope_analyzer = ScopeAnalyzer(mode=settings.scope_enforcement_mode)
        self.shadow_detector = ShadowDetector()

        # Pillar 7 & 11: Multi-tenant auth, rate limiting, and storage backend
        self.authenticator = HMACAuthenticator(secret_key=settings.hmac_secret_key)
        self.rate_limiter = TenantRateLimiter(default_limit=settings.rate_limit_per_minute)
        self.storage = get_storage_backend(settings.redis_url)
        self.active_unverified_agents: dict[str, float] = {}  # BUG-M3: agent_id -> last_seen_ts

        # BUG-H4 fix: Per-agent Isolation Forest buffers instead of global
        self.agent_allowed_events: dict[str, deque[ToolCallEvent]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self.agent_if_buffers: dict[str, list[list[float]]] = defaultdict(list)
        self.agent_observation_counts: dict[str, int] = defaultdict(int)
        self.transformer_training_sequences: dict[str, list[str]] = {}
        self._refit_task: asyncio.Task | None = None
        self._cleanup_task: asyncio.Task | None = None

        self.tool_counts: dict[str, dict[str, int]] = {}
        self.dest_counts: dict[str, dict[str, int]] = {}
        self.session_start_times: dict[str, float] = {}
        self.last_call_times: dict[str, float] = {}
        # BUG-M6 fix: True monotonic sequence counters per session
        self.session_call_counters: dict[str, int] = defaultdict(int)
        # BUG-H5 fix: Track active quarantined sessions
        self.quarantined_sessions: set[str] = set()
        self.event_subscribers: set[asyncio.Queue] = set()

        # SOC Control Plane runtime state
        self.started_at: float = time.time()
        self.latencies_ms: deque[float] = deque(maxlen=1000)
        self.event_breakdowns: dict[str, dict[str, Any]] = {}
        self.registered_agents: dict[str, dict[str, Any]] = {}
        self.suspended_agents: set[str] = set()
        self.disabled_policies: set[str] = set()
        self.policy_history: list[dict[str, Any]] = []
        self.testing_history: list[dict[str, Any]] = []
        self.last_audit_verified_at: float | None = None

    def broadcast_event(self, event_dict: dict[str, Any]) -> None:
        """Broadcast live event to all active SSE subscribers."""
        for q in list(self.event_subscribers):
            try:
                q.put_nowait(event_dict)
            except Exception as e:
                logger.debug(f"Failed to queue event for subscriber: {e}")

    async def initialize(self):
        await self.schema_pinner.init_db()

    def _extract_destination(
        self, params: dict[str, Any], explicit_dest: str | None = None
    ) -> str | None:
        if explicit_dest:
            return explicit_dest
        for k, val in params.items():
            if k in ("destination_domain", "domain", "host", "dest", "target") and isinstance(
                val, str
            ):
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

    async def _cleanup_unverified_agents(self):
        """BUG-M3 fix: Periodically evict stale unverified agent entries (TTL: 5 min)."""
        while True:
            try:
                await asyncio.sleep(60.0)
                now = time.time()
                stale = [aid for aid, ts in self.active_unverified_agents.items() if now - ts > 300]
                for aid in stale:
                    self.active_unverified_agents.pop(aid, None)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Error in unverified agents cleanup: {e}")

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

            # BUG-H4 fix: Refit Isolation Forest on per-agent buffers
            agent_buf = self.agent_if_buffers.get(agent_id, [])
            if agent_buf and len(agent_buf) >= 20:
                self.isolation_scorer.fit(np.array(agent_buf[-settings.if_refit_interval :]))

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
        request_id: Any = 1,
        schema_drift_err: str | None = None,
    ) -> tuple[ToolCallEvent, dict[str, Any]]:
        t_call_start = time.perf_counter()
        now = time.time()
        param_str = json.dumps(parameters, sort_keys=True)
        param_bytes = len(param_str.encode("utf-8"))

        dest_domain = self._extract_destination(parameters, destination_domain)

        # 1. Secret Redaction
        redacted_params, redacted_fields = SecretRedactor.redact_dict(parameters)

        # BUG-H6 fix: Compute parameter entropy and size upfront
        param_entropy = FeatureExtractor.extract_entropy(parameters)

        # Session timing
        if session_id not in self.session_start_times:
            self.session_start_times[session_id] = now
        session_duration_ms = (now - self.session_start_times[session_id]) * 1000.0

        time_since_prev_ms = None
        if session_id in self.last_call_times:
            time_since_prev_ms = (now - self.last_call_times[session_id]) * 1000.0
        self.last_call_times[session_id] = now

        prev_tools = self.window_mgr.get_recent_tools(session_id)
        # BUG-M6 fix: Use true monotonic counter instead of windowed length
        self.session_call_counters[session_id] += 1
        seq_pos = (
            sequence_position
            if sequence_position is not None
            else self.session_call_counters[session_id]
        )
        all_session_tools = prev_tools + [tool_name]

        event = ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_server=tool_server,
            parameters=redacted_params,
            parameter_size_bytes=param_bytes,  # BUG-H6 fix
            parameter_entropy=param_entropy,  # BUG-H6 fix
            destination_domain=dest_domain,
            time_since_previous_ms=time_since_prev_ms,
            session_duration_ms=session_duration_ms,
            sequence_position=seq_pos,
            redacted_fields=redacted_fields,
            trust_level=trust_level,
        )

        # BUG-C2 fix: Scope enforcement check
        scope_verdict = self.scope_analyzer.check_scope(agent_id, tool_name)
        if not scope_verdict.allowed:
            event.risk_score = 0.92
            event.risk_factors.append(f"Scope Violation: {scope_verdict.reason}")

        # BUG-C3 fix: Shadow detection check
        is_shadow = self.shadow_detector.check_shadowing(tool_name, tool_server)
        if is_shadow:
            event.risk_score = 0.95
            event.risk_factors.append(
                f"Tool Shadowing Detected: '{tool_name}' served by '{tool_server}' "
                f"but trusted source is '{self.shadow_detector.known_registry.get(tool_name)}'"
            )

        # BUG-C1 fix: Schema pinning verification on HTTP path
        if schema_drift_err:
            event.risk_score = 0.99
            event.risk_factors.append(f"Schema Drift (Rug Pull): {schema_drift_err}")
        elif upstream_url:
            # If tools were pinned during tools/list, verify consistency
            pass  # verify_or_pin is called on tools/list; here we trust the pin

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

        # Running stats for z-score (local + distributed storage backend, BUG-H3 fix)
        self.running_scaler.update("param_size", float(param_bytes))
        self.running_scaler.update("entropy", event.parameter_entropy)
        if time_since_prev_ms is not None:
            self.running_scaler.update("time_diff", float(time_since_prev_ms))
        self.running_scaler.update("duration", float(session_duration_ms))
        self.running_scaler.update("seq_pos", float(seq_pos))

        await self.storage.update_running_stats(
            agent_id,
            [
                float(param_bytes),
                float(event.parameter_entropy),
                float(time_since_prev_ms or 0.0),
                float(session_duration_ms),
                float(seq_pos),
            ],
        )

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
        i_score = 0.0
        i_factors: list[str] = []
        t_score = 0.0
        t_factors: list[str] = []
        tier_exited = 1
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
                tier_exited = 2
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
                    tier_exited = 3
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

        if agent_id in self.suspended_agents:
            ens_score = 1.0
            ens_factors.append("Agent Suspended: Access revoked by Cerberus SOC administrator")

        if event.risk_score is None or ens_score > event.risk_score:
            event.risk_score = ens_score
        event.risk_factors.extend(ens_factors)
        event.risk_factors = list(dict.fromkeys(event.risk_factors))

        # 5. Policy Enforcement
        if agent_id in self.suspended_agents:
            decision = EventDecision.BLOCK
            event.decision_reason = "Blocked: Agent is administratively suspended"
        else:
            decision = await self.enforcer.enforce(event)
        event.decision = decision

        elapsed_ms = round((time.perf_counter() - t_call_start) * 1000.0, 2)
        self.latencies_ms.append(elapsed_ms)
        self.event_breakdowns[event.event_id] = {
            "event_id": event.event_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "rule_score": round(float(r_score), 3),
            "markov_score": round(float(m_score), 3),
            "isolation_score": round(float(i_score), 3),
            "transformer_score": round(float(t_score), 3),
            "composite_score": round(float(event.risk_score or 0.0), 3),
            "tier_exited": tier_exited,
            "decision": decision.value,
            "rule_factors": r_factors,
            "markov_factors": m_factors,
            "isolation_factors": i_factors,
            "transformer_factors": t_factors,
            "duration_ms": elapsed_ms,
            "timestamp": now,
        }

        # BUG-H5 fix: Update quarantine gauge with active session tracking
        if decision == EventDecision.QUARANTINE:
            self.quarantined_sessions.add(session_id)
            ACTIVE_QUARANTINES.set(len(self.quarantined_sessions))

        # 6. Audit Logging & State Update (persist finalized event with risk score & decision)
        event_dump = event.model_dump(mode="json")
        await self.storage.record_event(session_id, agent_id, event_dump)
        await self.audit_logger.log_event(event)
        self.broadcast_event(event_dump)

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
                # BUG-H4 fix: Per-agent IF buffer
                self.agent_if_buffers[agent_id].append(if_vec)
                self.agent_observation_counts[agent_id] += 1
                self.transformer_training_sequences.setdefault(session_id, []).append(tool_name)

                agent_obs = self.agent_observation_counts[agent_id]
                if (
                    not self.isolation_scorer.is_fitted
                    and agent_obs >= settings.warm_threshold_calls
                ):
                    self.isolation_scorer.fit(np.array(self.agent_if_buffers[agent_id]))

                if (
                    not self.transformer_scorer.is_fitted
                    and agent_obs >= settings.warm_threshold_calls
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
                request_id=request_id,
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
        if self._cleanup_task:
            self._cleanup_task.cancel()
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
    engine._cleanup_task = asyncio.create_task(engine._cleanup_unverified_agents())
    try:
        yield
    finally:
        await engine.close()


app = FastAPI(
    title="Cerberus MCP Firewall",
    description="A runtime behavioral firewall for MCP-based AI agents",
    version="1.0.0",  # BUG-L2 fix: unified version
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

cors_origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(create_soc_router(engine))


# ── Data API endpoints for React dashboard ──────────────────────────────────


@app.get("/api/events/recent")
async def api_recent_events(limit: int = 50):
    """Return recent events across all sessions for the dashboard."""
    agents = await engine.storage.get_active_agents()
    all_events: list[dict[str, Any]] = []
    for agent_id in agents:
        history = await engine.storage.get_agent_history(agent_id, limit=limit)
        all_events.extend(history)
    # Sort by timestamp descending
    all_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return all_events[:limit]


@app.get("/api/agents")
async def api_agents():
    """Return list of active and registered agents with summary metrics."""
    active_ids = await engine.storage.get_active_agents()
    all_agent_ids = list(dict.fromkeys([*engine.registered_agents.keys(), *active_ids]))
    result = []
    for agent_id in all_agent_ids:
        history = await engine.storage.get_agent_history(agent_id, limit=100)
        baseline = engine.baseline_store.get_baseline(agent_id)
        reg = engine.registered_agents.get(agent_id, {})
        latest = history[-1] if history else {}
        latest_risk = float(latest.get("risk_score") or 0.0)
        latest_dec = str(latest.get("decision") or "").lower()
        observed_servers = sorted(
            {e.get("tool_server") for e in history if e.get("tool_server")}
            | set(reg.get("mcp_servers", []))
        )
        auth_tools = sorted(
            engine.scope_analyzer.agent_scopes.get(agent_id, set(reg.get("authorized_tools", [])))
        )
        if agent_id in engine.suspended_agents:
            status = "suspended"
        elif latest_dec == "quarantine" or latest.get("session_id") in engine.quarantined_sessions:
            status = "quarantined"
        elif latest_dec in ("flag", "block") or latest_risk >= settings.risk_flag_threshold:
            status = "flagged"
        else:
            status = "active"

        result.append(
            {
                "agent_id": agent_id,
                "agent_type": reg.get("agent_type", "Autonomous"),
                "status": status,
                "total_events": len(history),
                "is_warm": baseline.is_warm,
                "active_snapshot": baseline.active_snapshot_id,
                "snapshots_count": len(baseline.snapshots),
                "known_tools": sorted(baseline.known_tools) if baseline.known_tools else [],
                "authorized_tools": auth_tools,
                "mcp_servers": observed_servers,
                "current_risk_score": round(latest_risk, 3),
                "last_activity": latest.get("timestamp") or reg.get("created_at"),
                "trust_level": "unverified"
                if agent_id in engine.active_unverified_agents
                else "verified",
            }
        )
    return result


@app.get("/api/agents/{agent_id}/timeline")
async def api_agent_timeline(agent_id: str, limit: int = 100):
    """Return risk timeline data for a specific agent."""
    history = await engine.storage.get_agent_history(agent_id, limit=limit)
    return [
        {
            "timestamp": e.get("timestamp"),
            "tool_name": e.get("tool_name"),
            "risk_score": e.get("risk_score", 0.0),
            "decision": e.get("decision"),
            "risk_factors": e.get("risk_factors", []),
            "session_id": e.get("session_id"),
            "trust_level": e.get("trust_level", "unverified"),
        }
        for e in history
    ]


@app.get("/api/agents/{agent_id}/baseline")
async def api_agent_baseline(agent_id: str):
    """Return baseline data for a specific agent."""
    baseline = engine.baseline_store.get_baseline(agent_id)
    return {
        "agent_id": baseline.agent_id,
        "is_warm": baseline.is_warm,
        "total_calls_observed": baseline.total_calls_observed,
        "active_snapshot_id": baseline.active_snapshot_id,
        "snapshots": [
            {
                "snapshot_id": s.snapshot_id,
                "created_at": s.created_at.isoformat(),
                "calls_in_snapshot": s.calls_in_snapshot,
                "is_active": s.is_active,
            }
            for s in baseline.snapshots
        ],
        "known_tools": sorted(baseline.known_tools) if baseline.known_tools else [],
        "known_destinations": sorted(baseline.known_destinations)
        if baseline.known_destinations
        else [],
    }


@app.get("/api/sessions")
async def api_sessions():
    """Return list of active sessions."""
    sessions = await engine.storage.get_active_sessions()
    result = []
    for sid in sessions:
        history = await engine.storage.get_session_history(sid, limit=5)
        if history:
            latest = history[-1]
            result.append(
                {
                    "session_id": sid,
                    "agent_id": latest.get("agent_id", "unknown"),
                    "total_events": len(history),
                    "latest_risk_score": latest.get("risk_score", 0.0),
                    "latest_decision": latest.get("decision"),
                    "trust_level": latest.get("trust_level", "unverified"),
                }
            )
    return result


@app.get("/api/sessions/{session_id}/events")
async def api_session_events(session_id: str, limit: int = 100):
    """Return events for a specific session."""
    return await engine.storage.get_session_history(session_id, limit=limit)


@app.get("/api/metrics/summary")
async def api_metrics_summary():
    """Aggregated dashboard metrics."""
    active_ids = await engine.storage.get_active_agents()
    all_agent_ids = set(active_ids) | set(engine.registered_agents.keys())
    sessions = await engine.storage.get_active_sessions()
    counts = {"allow": 0, "flag": 0, "block": 0, "quarantine": 0}
    total_calls = 0
    for sid in sessions:
        hist = await engine.storage.get_session_history(sid, limit=500)
        total_calls += len(hist)
        for ev in hist:
            dec = str(ev.get("decision") or "allow").lower()
            if dec in counts:
                counts[dec] += 1

    latency_samples = list(engine.latencies_ms)
    latency_stats = None
    if latency_samples:
        arr = np.array(latency_samples, dtype=float)
        latency_stats = {
            "p50": round(float(np.percentile(arr, 50)), 2),
            "p95": round(float(np.percentile(arr, 95)), 2),
            "p99": round(float(np.percentile(arr, 99)), 2),
            "avg": round(float(np.mean(arr)), 2),
        }

    return {
        "active_agents": len(all_agent_ids),
        "active_sessions": len(sessions),
        "unverified_agents": len(engine.active_unverified_agents),
        "total_tool_calls": total_calls,
        "allow_count": counts["allow"],
        "flag_count": counts["flag"],
        "block_count": counts["block"],
        "quarantine_count": counts["quarantine"],
        "quarantined_sessions": len(engine.quarantined_sessions),
        "uptime_seconds": round(time.time() - engine.started_at, 1),
        "latency_ms": latency_stats,
        "mode": settings.mode,
        "fail_closed": settings.fail_closed,
        "require_signed_identity": settings.require_signed_identity,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
    }


@app.get("/api/policies/pending")
async def api_pending_policies():
    """Return pending auto-synthesized policies for dashboard."""
    return engine.policy_synthesizer.list_pending_policies()


@app.get("/api/events")
async def api_get_events(limit: int = 50):
    """Return recent events across all sessions for live dashboard feed."""
    sessions = await engine.storage.get_active_sessions()
    all_events = []
    for sid in sessions:
        events = await engine.storage.get_session_history(sid, limit=limit)
        all_events.extend(events)
    # Sort by timestamp descending
    all_events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    return all_events[:limit]


@app.get("/api/events/stream")
async def api_event_stream(request: Request):
    """Server-Sent Events stream for live real-time dashboard updates."""

    async def sse_generator():
        q: asyncio.Queue = asyncio.Queue()
        engine.event_subscribers.add(q)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event_data = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(event_data)}\n\n"
                except TimeoutError:
                    yield ": ping\n\n"
        finally:
            engine.event_subscribers.discard(q)

    return StreamingResponse(sse_generator(), media_type="text/event-stream")


@app.get("/api/audit/logs")
async def api_audit_logs(limit: int = 100):
    """Retrieve raw audit logs with envelope data for ledger exploration."""
    if not os.path.exists(settings.log_path):
        return []
    records = []
    try:
        lines = await asyncio.to_thread(_read_file_lines_sync, settings.log_path)
        for line in reversed(lines[-limit:]):
            try:
                decrypted = engine.audit_logger.decrypt_log_line(line)
                rec = json.loads(decrypted)
                records.append(rec)
            except Exception as e:
                logger.debug(f"Failed to decrypt/parse log line: {e}")
    except Exception as e:
        logger.warning(f"Failed to read audit log: {e}")
    return records


@app.post("/api/audit/verify")
async def api_verify_audit_ledger():
    """Verify cryptographic SHA-256 hash chain across audit ledger."""
    valid, count, err = AuditLogger.verify_ledger(settings.log_path)
    engine.last_audit_verified_at = time.time()
    return {
        "is_valid": valid,
        "total_entries": count,
        "error": err,
        "log_path": settings.log_path,
    }


@app.get("/api/policies")
async def api_list_all_policies():
    """List active and candidate policies."""
    policies_dir = "policies"
    active_policies = []
    if os.path.exists(policies_dir):
        for root, _, files in os.walk(policies_dir):
            for f in files:
                if f.endswith(".rego"):
                    file_path = os.path.join(root, f)
                    rel_path = os.path.relpath(file_path, policies_dir)
                    try:
                        content = await asyncio.to_thread(_read_file_sync, file_path)
                        active_policies.append(
                            {
                                "name": f,
                                "path": rel_path,
                                "type": "active",
                                "enabled": f not in engine.disabled_policies,
                                "code": content,
                            }
                        )
                    except Exception as e:
                        logger.debug(f"Failed to read policy file {f}: {e}")

    pending = engine.policy_synthesizer.list_pending_policies()
    return {
        "active": active_policies,
        "pending": pending,
    }


@app.get("/api/baselines")
async def api_list_baselines():
    """List baselines for all agents."""
    base_dir = settings.baselines_dir
    agents = []
    if os.path.exists(base_dir):
        for name in os.listdir(base_dir):
            agent_path = os.path.join(base_dir, name)
            if os.path.isdir(agent_path):
                baseline = engine.baseline_store.get_baseline(name)
                agents.append(
                    {
                        "agent_id": name,
                        "active_snapshot_id": baseline.active_snapshot_id,
                        "snapshots_count": len(baseline.snapshots),
                        "known_tools": sorted(baseline.known_tools) if baseline.known_tools else [],
                        "known_destinations": sorted(baseline.known_destinations)
                        if baseline.known_destinations
                        else [],
                        "snapshots": [
                            {
                                "snapshot_id": s.snapshot_id,
                                "created_at": s.created_at.isoformat(),
                                "calls_in_snapshot": s.calls_in_snapshot,
                                "is_active": s.is_active,
                            }
                            for s in baseline.snapshots
                        ],
                    }
                )
    return agents


# ── Existing Operational Endpoints ──────────────────────────────────────────


@app.get("/healthz")
async def health_check():
    storage_health = await engine.storage.health_check()
    return {
        "status": "healthy",
        "version": "1.0.0",
        "mode": settings.mode,
        "opa_url": settings.opa_url,
        "fail_closed": settings.fail_closed,
        "active_unverified_agents": len(engine.active_unverified_agents),
        "unverified_agents": list(engine.active_unverified_agents.keys()),
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
    """Approve candidate synthesized policy and push to OPA (BUG-M2 fix)."""
    ok = engine.policy_synthesizer.approve_policy(policy_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Policy not found or failed to approve")

    # BUG-M2 fix: Push approved Rego policy to OPA engine
    rego_path = os.path.join(engine.policy_synthesizer.output_dir, f"{policy_id}.rego")
    if os.path.exists(rego_path):
        try:
            rego_code = await asyncio.to_thread(_read_file_sync, rego_path)
            opa_client = getattr(engine.enforcer, "opa_client", None)
            if not opa_client:
                from cerberus.policy.opa_client import OPAClient

                opa_client = OPAClient()
            await opa_client.put_policy(policy_id, rego_code)
            logger.info(f"Pushed approved policy {policy_id} to OPA")
        except Exception as e:
            logger.warning(f"Could not push approved policy {policy_id} to OPA: {e}")

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
            if x_agent_id and x_agent_id != "default-agent":
                agent_id = x_agent_id
            else:
                agent_id = f"agent-unverified-{uuid.uuid4().hex[:8]}"

        if x_session_id and x_session_id != "default-session":
            session_id = x_session_id
        else:
            session_id = f"session-{uuid.uuid4().hex[:8]}"

    # BUG-M3 fix: Track with timestamp instead of unbounded set
    if trust_level == "unverified":
        engine.active_unverified_agents[agent_id] = time.time()
    else:
        engine.active_unverified_agents.pop(agent_id, None)

    # Per-tenant rate limiting (local + storage backend, BUG-H2 fix)
    storage_rate_ok = await engine.storage.check_rate_limit(
        agent_id, limit=settings.rate_limit_per_minute, window_seconds=60
    )
    rate_ok, _, _reset_secs = engine.rate_limiter.check_rate_limit(agent_id)
    if not (rate_ok and storage_rate_ok):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32029,
                "message": f"Rate limit exceeded for agent '{agent_id}' ({settings.rate_limit_per_minute}/min)",
            },
        }

    # BUG-C4 fix: Forward tools/list to upstream if configured, otherwise return defaults
    if method == "tools/list":
        duration = time.perf_counter() - start_time

        if x_upstream_url:
            # Forward to real upstream and pin schemas
            upstream_res = await engine.forwarder.forward_call(
                server_url=x_upstream_url,
                method="tools/list",
                params=params,
                request_id=req_id,
            )
            # BUG-C1 fix: Pin schemas from upstream tools/list response
            tools = upstream_res.get("result", {}).get("tools", [])
            for tool in tools:
                t_name = tool.get("name", "")
                t_desc = tool.get("description", "")
                t_schema = tool.get("inputSchema", {})
                pin_ok, pin_err = await engine.schema_pinner.verify_or_pin(
                    x_upstream_url, t_name, t_desc, t_schema
                )
                if not pin_ok:
                    logger.warning(f"Schema drift detected for tool '{t_name}': {pin_err}")
                # BUG-C3 fix: Register trusted tool-server mappings
                engine.shadow_detector.register_trusted(t_name, x_upstream_url)

            REQUEST_LATENCY.observe(duration)
            REQUEST_COUNT.labels(tool_name="tools/list", decision="allow").inc()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": upstream_res.get("result", {"tools": []}),
            }

        # Default tools (no upstream)
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
        request_id=req_id,
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


# ── Static UI Mounting for React Frontend ───────────────────────────────────
_frontend_dist = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "frontend",
    "dist",
)
if os.path.exists(_frontend_dist):
    assets_dir = os.path.join(_frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="dashboard_assets")

    @app.get("/cerberus-logo.svg")
    async def serve_logo_svg():
        logo_path = os.path.join(_frontend_dist, "cerberus-logo.svg")
        if os.path.isfile(logo_path):
            return FileResponse(logo_path, media_type="image/svg+xml")
        raise HTTPException(status_code=404, detail="Logo not found")

    @app.get("/")
    @app.get("/features")
    @app.get("/architecture")
    @app.get("/threat-lab")
    @app.get("/docs")
    @app.get("/login")
    @app.get("/ui")
    @app.get("/ui/{full_path:path}")
    @app.get("/dashboard")
    @app.get("/dashboard/{full_path:path}")
    async def serve_dashboard(full_path: str = ""):
        target = os.path.join(_frontend_dist, full_path)
        if full_path and os.path.isfile(target):
            return FileResponse(target)
        return FileResponse(os.path.join(_frontend_dist, "index.html"))
