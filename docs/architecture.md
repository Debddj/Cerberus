# Cerberus System Architecture

Cerberus is a runtime behavioral firewall positioned between autonomous AI agents and Model Context Protocol (MCP) tool servers.

## 1. Pipeline Overview
- **Ingress Interception:** Receives MCP client JSON-RPC requests via FastAPI gateway.
- **Pre-Execution Scanning:**
  - Validates cryptographic SHA-256 tool description pins.
  - Checks for the Lethal Trifecta (Private Data + Untrusted Content + External Egress).
  - Validates permission boundaries.
- **Behavioral Drift Scoring:**
  - Extracts Markov features (categorical) and Isolation Forest features (continuous, scaled).
  - Scores sequence transitions using Markov Chain surprise squashed through a sigmoid function.
  - Detects multivariate feature anomalies via Isolation Forest.
  - Combines outputs in a weighted ensemble with a high-threat circuit breaker.
- **Policy Enforcement (OPA):**
  - Evaluates inputs against Rego policies.
  - Emits decisions: `ALLOW`, `FLAG`, `BLOCK`, `QUARANTINE`.
  - Enforces **Fail-Closed** defaults during OPA outages.
- **Narrative Reconstruction:**
  - Assembles audit logs into human-readable attack chains (Reconnaissance -> Staging -> Exfiltration).

## 2. Failure Mode Analysis
| Subsystem Failure | Default Behavior | Security Rationale |
|---|---|---|
| OPA Policy Engine Outage | **Fail-Closed** for high-risk / unbaselined calls | Prevents intentional DoS attacks against policy service to bypass defenses |
| Behavioral Engine Latency Spike | Circuit breaker timeout at 50ms, falls back to Static + Rule Scorer | Keeps agent interaction responsive without opening full bypass |
| Database Corruption / Lock | In-memory fallback buffer with alert emission | Prevents denial of tool service for legitimate agents |
