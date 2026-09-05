# Cerberus System Architecture

Cerberus is an industry-grade runtime behavioral firewall positioned between autonomous AI agents and Model Context Protocol (MCP) tool servers. It monitors sequences of tool calls in real time to detect emerging multi-step attack chains, enforce declarative Open Policy Agent (OPA) policies, and reconstruct forensic attack narratives.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AI Agent (tool-calling loop)                │
│                                                                     │
│   Agent sends tool_call requests thinking it talks to MCP servers   │
└─────────────────────────┬───────────────────────────────────────────┘
                          │ JSON-RPC (HTTP / Streamable)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    CERBERUS INTERCEPTION PROXY                      │
│                  (FastAPI + asyncio + /metrics)                     │
│                                                                     │
│  ┌──────────┐    ┌──────────────────┐    ┌───────────────────────┐  │
│  │ Ingress  │───▶│  Request Router  │───▶│  Response Aggregator  │  │
│  │ Handler  │    │  & Logger        │    │  & Logger             │  │
│  └──────────┘    └────────┬─────────┘    └───────────┬───────────┘  │
│                           │                          │              │
│               ┌───────────┴──────────┐               │              │
│               │  SECRET REDACTOR     │               │              │
│               │  (pre-log filtering) │               │              │
│               └───────────┬──────────┘               │              │
│                    ┌──────┴──────────────────────┐   │              │
│                    ▼                             ▼   ▼              │
│  ┌─────────────────────┐  ┌───────────────────────────────────┐    │
│  │   STATIC SCANNER    │  │      BEHAVIORAL ENGINE            │    │
│  │                     │  │                                   │    │
│  │  • Schema Pinning   │  │  • Feature Extractor              │    │
│  │    (SHA-256 hash)   │  │  • Sequence Window (n-gram)       │    │
│  │  • Lethal Trifecta  │  │  • Per-Agent Baseline Store       │    │
│  │    Detector         │  │    (versioned + stability-gated)  │    │
│  │  • Permission Scope │  │  • Scoring Pipeline:              │    │
│  │    Analysis         │  │    ├─ Rule-Based (floor & pre-base)│    │
│  │  • Tool Shadowing   │  │    ├─ Markov Chain (categorical)  │    │
│  │    Check            │  │    ├─ Isolation Forest (continuous)│    │
│  │  └─────────┬───────────┘  │    └─ Sequence Transformer (AE)   │    │
│            │              │  • Score Explainer                │    │
│            │              └──────────────┬────────────────────┘    │
│            │                             │                         │
│            └──────────┬──────────────────┘                         │
│                       ▼                                            │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │              POLICY ENGINE (Open Policy Agent)            │     │
│  │                                                           │     │
│  │  • Hand-crafted Rego rules (rug-pull, lethal trifecta)    │     │
│  │  • Behavioral score thresholds (allow/flag/block/quarantine)│    │
│  │  • Auto-synthesized least-privilege policies              │     │
│  │  • FAIL-CLOSED DEFAULT with circuit breaker on outage     │     │
│  └───────────────────────┬───────────────────────────────────┘     │
│                           │                                        │
│              ┌────────────┴────────────┐                           │
│              │   DECISION: ✅ ALLOW    │                           │
│              │            ⚠️ FLAG     │                           │
│              │            🛑 BLOCK    │                           │
│              │            🔒 QUARANTINE│                           │
│              └────────────┬────────────┘                           │
└───────────────────────────┼────────────────────────────────────────┘
                            │
           ┌────────────────┴────────────────────────┐
           ▼                                         ▼
┌───────────────────────┐              ┌──────────────────────────┐
│  MCP Tool Servers     │              │  DASHBOARD (Streamlit)   │
│  (GitHub, Slack, DB,  │              │                          │
│   Cloud APIs, etc.)   │              │  • Live session list     │
│                       │              │  • Risk score timeline   │
│  Running in Docker    │              │  • Attack story viewer   │
│  Compose sandbox      │              │  • Policy approval UI    │
│                       │              │  • Baseline health view  │
└───────────────────────┘              └──────────────────────────┘
```

---

## 1. Pipeline Deep Dive

### 1.1 Ingress & Routing
The proxy acts as an MCP transparent proxy. Clients target `http://cerberus-proxy:8000/mcp` as their upstream server.
- Intercepts `tools/list` to inspect schemas and establish pins before runtime invocation.
- Intercepts `tools/call` JSON-RPC envelopes, binding session IDs, sequence positions, and agent IDs.

### 1.2 Static Pre-Flight Scanner
Before execution or behavioral modeling, lightweight deterministic checks execute:
1. **Schema Pinning (`SchemaPinner`):** Computes `SHA-256(description + input_schema_json)`. Any alteration mid-session trips an immediate `SCHEMA_DRIFT` deny rule.
2. **Lethal Trifecta Detector (`TrifectaDetector`):** Checks whether an agent's available tools span Private Data Access, Untrusted Content Ingestion, and External Egress.
3. **Permission Scope Analyzer (`ScopeAnalyzer`):** Blocks administrative or out-of-scope capabilities.
4. **Tool Shadow Detector (`ShadowDetector`):** Prevents namespace collisions and masquerading tools.

### 1.3 Behavioral Drift Engine
Operates on sliding windows of tool invocations, addressing sequence-level multi-step attack chains:
- **Clean Feature Separation:**
  - `MarkovFeatures`: Categorical tool-to-tool transitions. Surprise $- \log_2(P(t_i | t_{i-1}))$ is normalized via sigmoid squashing:
    $$S(x) = rac{1}{1 + e^{-0.8(x - 4.0)}}$$
  - `IsolationForestFeatures`: Continuous features only (parameter entropy, parameter size, response size, inter-call timing, session duration, sequence position). Normalized via per-agent robust z-score scaling.
  - `SequenceTransformerScorer`: PyTorch sequence autoencoder measuring sequence reconstruction cross-entropy.
  - `RuleScorer`: Serves as the pre-baseline security floor active on call #1 before statistical baselines warm up.
- **Ensemble Circuit Breaker:**
  Weighted average with high-threat escalation: if rule score $\ge 0.75$ or an ML engine score $\ge 0.90$, the composite score escalates directly to prevent un-warmed baseline squashing.

### 1.4 Open Policy Agent (OPA) Integration & Fail-Closed Behavior
Cerberus queries an OPA REST sidecar using Rego v1 policies (`policies/base/`):
- `rug_pull.rego`: Blocks schema drift.
- `trifecta.rego`: Denies unrestricted trifecta sessions.
- `privilege_escalation.rego`: Blocks unscoped administrative capabilities.
- `behavioral.rego`: Routes composite risk scores:
  - $< 0.40 ightarrow 	ext{ALLOW}$
  - $[0.40, 0.70) ightarrow 	ext{FLAG}$
  - $[0.70, 0.90) ightarrow 	ext{BLOCK}$
  - $\ge 0.90 ightarrow 	ext{QUARANTINE}$
- **Fail-Closed Circuit Breaker:** When OPA is unreachable, Cerberus caches the outage for 10 seconds to avoid per-call socket timeouts. High-risk calls ($\ge 0.70$) and any calls triggering static alerts are unconditionally **BLOCKED**. Only low-risk, warm-baselined calls degrade to logging-only allow.

---

## 2. Failure Mode Analysis

| Subsystem Failure | Default Behavior | Security Rationale |
|---|---|---|
| **OPA Policy Engine Outage** | **Fail-Closed** for high-risk / unbaselined calls | Prevents intentional DoS attacks against policy service from opening an authorization bypass. |
| **Behavioral Engine Latency Spike** | Circuit breaker timeout at 50ms, falls back to Static + Rule Scorer | Keeps agent interaction responsive (<50ms P99) without dropping security floor. |
| **Database Corruption / Lock** | In-memory fallback buffer with alert emission | Prevents denial-of-service for legitimate agent transactions. |
| **Log Storage Exhaustion** | In-memory ring buffer with backpressure alert | Guarantees audit compliance without crashing agent execution. |

---

## 3. Empirical Latency Envelope

From benchmark evaluation across 1,000 live tool-call intercepts:
- **P50 Latency:** **12.22 ms** (target < 15.0 ms)
- **P95 Latency:** **14.02 ms** (target < 25.0 ms)
- **P99 Latency:** **15.43 ms** (target < 50.0 ms)
