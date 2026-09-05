import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, Request, Response

from cerberus.behavioral.ensemble import EnsembleScorer
from cerberus.behavioral.features import FeatureExtractor
from cerberus.behavioral.scaling import RunningScaler
from cerberus.behavioral.scorers.isolation import IsolationForestScorer
from cerberus.behavioral.scorers.markov import MarkovScorer
from cerberus.behavioral.scorers.rule_based import RuleBasedScorer
from cerberus.behavioral.window import SessionWindowManager
from cerberus.config import settings
from cerberus.policy.enforcer import EnforcementPipeline
from cerberus.proxy.forwarder import UpstreamMCPForwarder
from cerberus.proxy.logger import AuditLogger
from cerberus.proxy.metrics import REQUEST_COUNT, REQUEST_LATENCY, get_metrics_payload
from cerberus.proxy.models import EventDecision, ToolCallEvent
from cerberus.proxy.redactor import SecretRedactor
from cerberus.scanner.schema_pinner import SchemaPinner
from cerberus.scanner.trifecta import LethalTrifectaDetector

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
        self.rule_scorer = RuleBasedScorer()
        self.ensemble_scorer = EnsembleScorer()
        self.schema_pinner = SchemaPinner(db_path=settings.pins_db_path)
        self.enforcer = EnforcementPipeline()
        self.forwarder = UpstreamMCPForwarder()
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

    async def process_tool_call(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_server: str,
        parameters: dict[str, Any],
        destination_domain: str | None = None,
        sequence_position: int | None = None,
        upstream_url: str | None = None,
    ) -> tuple[ToolCallEvent, dict[str, Any]]:
        now = time.time()
        start_t = self.session_start_times.setdefault(session_id, now)
        last_t = self.last_call_times.get(session_id)
        time_since_prev_ms = ((now - last_t) * 1000.0) if last_t is not None else None
        self.last_call_times[session_id] = now
        session_duration_ms = (now - start_t) * 1000.0

        # 1. Secret Redaction on parameters
        redacted_params, redacted_fields = SecretRedactor.redact_dict(parameters)
        dest_domain = self._extract_destination(parameters, destination_domain)
        param_bytes = len(json.dumps(redacted_params).encode("utf-8"))

        # Previous tools in session
        prev_tools = self.window_mgr.get_recent_tools(session_id)
        seq_pos = sequence_position if sequence_position is not None else len(prev_tools)

        event = ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_server=tool_server,
            parameters=redacted_params,
            parameter_size_bytes=param_bytes,
            parameter_entropy=FeatureExtractor.extract_entropy(redacted_params),
            destination_domain=dest_domain,
            time_since_previous_ms=time_since_prev_ms,
            session_duration_ms=session_duration_ms,
            sequence_position=seq_pos,
            redacted_fields=redacted_fields,
        )

        # 2. Static Checks: Lethal Trifecta
        all_session_tools = prev_tools + [tool_name]
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

        # 4. Behavioral Scoring
        r_score, r_factors = self.rule_scorer.score(rule_f)
        m_score, m_factors = self.markov_scorer.score(markov_f)
        i_score, i_factors = self.isolation_scorer.score(if_f)

        ens_score, ens_factors = self.ensemble_scorer.combine(
            rule_score=r_score,
            markov_score=m_score,
            isolation_score=i_score,
            rule_factors=r_factors,
            markov_factors=m_factors,
            isolation_factors=i_factors,
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


engine = CerberusProxyEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await engine.initialize()
    yield


app = FastAPI(
    title="Cerberus MCP Firewall",
    description="A runtime behavioral firewall for MCP-based AI agents",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/healthz")
async def health_check():
    return {
        "status": "healthy",
        "mode": settings.mode,
        "opa_url": settings.opa_url,
        "fail_closed": settings.fail_closed,
    }


@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics_payload(), media_type="text/plain; version=0.0.4")


@app.post("/mcp")
async def mcp_proxy_gateway(
    request: Request,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    x_upstream_url: str | None = Header(default=None, alias="X-Upstream-URL"),
):
    start_time = time.perf_counter()
    body = await request.json()
    req_id = body.get("id", 1)
    method = body.get("method", "tools/call")
    params = body.get("params", {})

    session_id = x_session_id or params.get("session_id", "session-default")
    agent_id = x_agent_id or params.get("agent_id", "agent-default")

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
