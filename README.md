# Cerberus 🛡️

**A Runtime Behavioral Firewall for MCP-Based AI Agents**

> *mcp-scan asks "is this tool description safe before I connect"; Cerberus asks "does this agent's behavior over the last N calls still look like itself."*

---

## 1. Executive Summary

Every AI agent today interacts with external systems via tools (filesystems, databases, GitHub, Slack, cloud APIs). The Model Context Protocol (MCP) has rapidly become the standard interface for tool interactions, but shipped without native runtime security boundaries. Over 40 CVEs and widespread disclosures have demonstrated that tool poisoning, prompt injections, and rogue behaviors are persistent enterprise threats.

Traditional defenses ask a single question: **"Is this specific tool call allowed?"**
Cerberus addresses the critical unsolved challenge: **"Does this sequence of individually-authorized tool calls tell an attack story?"**

A prompt-injected agent that reads a private repo, subsequently queries a database, and makes an outbound HTTP POST 20 seconds later performs actions that may appear benign in isolation. Cerberus discovers the attack by tracking and evaluating the **sequence chain**.

```
AI agent (tool-calling loop)
        │
        ▼
Cerberus Interception Proxy ───────────────► Dashboard (attack narratives & audit)
        │
   ┌────┴────────────────────────┐
   ▼                             ▼
Static Scanner            Behavioral Engine
(Schema Pin, Trifecta)    (Markov, Isolation Forest, Transformer)
   │                             │
   └─────────────┬───────────────┘
                 ▼
          Policy Engine (OPA)
                 │
                 ▼
MCP Tool Servers (GitHub, Databases, Slack, Webhooks)
```

---

## 2. Core Architecture

Cerberus operates as an intelligent guardian gateway:
1. **Interception Proxy:** FastAPI/asyncio man-in-the-middle gateway with automated secret redaction, audit logging, and Prometheus telemetry.
2. **Static Scanner:** Pre-flight SHA-256 schema pinning to prevent "rug pull" modifications, permission scope validation, and detection of the **Lethal Trifecta** (Private Data Access + Untrusted Content Exposure + External Egress).
3. **Behavioral ML Engine:**
   - **Markov Chain Scorer:** Evaluates categorical tool-to-tool transition probabilities with bounded sigmoid squashing.
   - **Isolation Forest Scorer:** Analyzes multi-dimensional continuous features (entropy, payload sizes, inter-call timing, novelty) scaled with per-agent z-scores.
   - **Sequence Transformer Autoencoder:** Neural sequence representation learning detecting complex transition anomalies.
   - **Versioned Baselines with Stability Gating:** Protects against "boiling frog" baseline poisoning attacks by excluding flagged sessions.
4. **Policy Engine (OPA):** Rego-based authorization with synthesized least-privilege policies, human approval checkpoints, and a **fail-closed default** during upstream outages.
5. **Incident Narrative Reconstructor:** Rebuilds fragmented log streams into human-readable attack stories across reconnaissance, staging, and exfiltration phases.

---

## 3. Threat Taxonomy Mapping

| Framework | Risk Code | Cerberus Defense Mechanism |
|---|---|---|
| **OWASP Agentic Top 10** | ASI01: Agent Goal Hijack | Markov & Isolation Forest sequence drift scoring |
| **OWASP Agentic Top 10** | ASI02: Tool Misuse & Exploitation | OPA policy enforcement + parameter entropy checks |
| **OWASP Agentic Top 10** | ASI03: Identity & Privilege Abuse | Scope analyzer + out-of-scope invocation blocker |
| **OWASP Agentic Top 10** | ASI04: Supply Chain Vulnerabilities | SHA-256 Schema Pinning (rug-pull detection) |
| **OWASP Agentic Top 10** | ASI10: Rogue Agents | Mid-session session quarantine |
| **OWASP MCP Top 10** | Tool Poisoning & Shadowing | Schema pinner & tool shadow detector |
| **NSA CSI (May 2026)** | Dynamic Tool Invocation | Runtime behavioral interceptor & least-privilege synthesis |

---

## 4. Benchmark & Evaluation Results

Cerberus was benchmarked against standard attacks and adversarial evasion techniques across four agent archetypes (**Coding**, **Data Analysis**, **Customer Support**, and **Web Research / Triage**).

| Metric | Measured Value | Design Target | Status |
|---|---|---|---|
| **Standard Attack Detection (TPR)** | **100.0%** | > 90.0% | [MET] |
| **Adversarial Evasion Resistance (TPR)** | **66.7%** | > 50.0% | [MET] |
| **Overall False Positive Rate (FPR)** | **0.00%** | < 5.0% | [MET] |
| **P50 Latency Overhead** | **12.22 ms** | < 15.0 ms | [MET] |
| **P95 Latency Overhead** | **14.02 ms** | < 25.0 ms | [MET] |
| **P99 Latency Overhead** | **15.43 ms** | < 50.0 ms | [MET] |

*Detailed benchmark breakdown and evasion analysis available in [docs/evaluation-report.md](docs/evaluation-report.md).*

---

## 5. Quickstart

### Prerequisites
- Python 3.12+
- `uv` package manager (`pip install uv`)
- Docker & Docker Compose

### Local Development Setup
```bash
# Clone the repository
git clone https://github.com/Debddj/Cerberus.git
cd cerberus

# Install dependencies
uv venv
uv pip install -e ".[dev]"

# Run tests
uv run pytest -v

# Run evaluation benchmark
uv run python evaluation/run_evaluation.py
```

### Running the Docker Sandbox
```bash
docker compose up -d
```
- Proxy available at `http://localhost:8000`
- Prometheus Metrics at `http://localhost:8000/metrics`
- Streamlit Dashboard at `http://localhost:8501`

---

## 6. Repository Structure

```
cerberus/
├── docs/                     # Architecture, threat models, evaluation report
├── policies/                 # Rego policies (base, generated, tests)
├── sandbox/                  # Dockerized mock MCP servers and test agents
├── src/cerberus/
│   ├── behavioral/           # Markov, Isolation Forest, Transformer, Scaling
│   ├── dashboard/            # Streamlit real-time incident monitor
│   ├── narrative/            # Attack story reconstruction engine
│   ├── policy/               # OPA client and policy synthesizer
│   ├── proxy/                # Interception gateway, logger, redactor, server
│   └── scanner/              # Schema pinner, lethal trifecta detector
└── tests/                    # Unit, integration, and E2E evasion test suites
```

---

## 7. License
Licensed under the [Apache-2.0 License](LICENSE).
