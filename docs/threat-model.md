# Cerberus Meta-Security & Self-Defense Threat Model

A security firewall that does not defend itself becomes an organization's most dangerous liability. Cerberus explicitly models and implements defenses against three self-referential attacks:

---

## 1. Policy Engine Denial of Service / Crash

### The Threat
An attacker aware of Cerberus's presence sends malformed inputs or floods the OPA sidecar to trigger crash loops, connection timeouts, or resource exhaustion. In naive systems, policy evaluation fails open, allowing the attacker to execute arbitrary tool calls unimpeded.

### Cerberus Defense
- **Strict Fail-Closed Default:** If OPA fails to respond within timeout (or is unreachable), `OPAClient` evaluates local fail-closed logic:
  - Any call triggering a static scanner alert (schema drift, trifecta, out-of-scope) is **BLOCKED**.
  - Any call with an ensemble behavioral risk score $\ge 0.70$ is **BLOCKED**.
  - Calls during an unformed baseline (cold start) are **BLOCKED**.
  - Only confirmed low-risk calls on warm baselines degrade to logging-only allow.
- **Outage Circuit Breaker:** `OPAClient` trips a 10-second circuit breaker upon connection failure, caching the outage state and avoiding 1–2 second OS socket timeout stalls per call while maintaining instant fail-closed enforcement.

---

## 2. Audit Log as an Exfiltration Vector

### The Threat
Tool interception proxies capture full parameter payloads and response contents. If prompts contain database passwords, API tokens, customer PII, or private keys, the firewall's persistent audit log becomes an unencrypted, centralized treasure trove for attackers.

### Cerberus Defense
- **Pre-Persistence Secret Redactor (`SecretRedactor`):**
  - Evaluates regular expressions across tool parameters, source prompts, and response summaries before serialization.
  - Matches API keys, GitHub PATs (`ghp_`), OpenAI tokens (`sk-`), AWS access keys (`AKIA`), private RSA key headers, and Bearer authorization tokens.
  - Replaces sensitive strings with `[REDACTED]`.
  - Records redacted field names in `ToolCallEvent.redacted_fields` for audit transparency without persisting the raw secret.
- **Encryption at Rest:** Persisted event storage is compatible with AES-256-GCM application encryption and encrypted SQLite.

---

## 3. Baseline Poisoning ("Boiling Frog" Attacks)

### The Threat
A patient attacker does not trigger high-risk actions in a single session. Instead, they introduce minuscule behavioral drift across hundreds of calls, gradually training the anomaly detection models to accept malicious patterns as the new normal.

### Cerberus Defense
- **Immutable Versioned Snapshots:** Baselines are stored as discrete, immutable snapshots (`BaselineSnapshot`), not continuously mutating unconstrained sliding windows.
- **Stability Gating:** Any session containing even a single flagged ($	ext{score} \ge 0.40$) or quarantined call is permanently excluded from baseline retraining datasets.
- **Human Review & Rollback:** The SOC dashboard alerts on unreviewed baselines and provides an instantaneous, one-click rollback mechanism to restore an agent to an earlier known-clean snapshot (e.g., `snap_v3` → `snap_v2`).

---

## 4. Empirical Evasion Analysis

In benchmark evaluations against adaptive evasion techniques:
- **Slow-Drip Exfiltration:** Small chunks (<150 bytes, entropy ~4.1 bits) were allowed individually, but caught at **Call #10** (Risk: 0.75, Blocked) when cumulative egress volume and burst frequency crossed behavioral limits.
- **Markov Mimicry:** The attacker executed a legitimate coding sequence (`read_file` → `write_file` → `run_tests`) with hostile arguments. Structural Markov modeling was bypassed (Risk: 0.24, Allow), demonstrating that pure syntax modeling must be complemented by semantic parameter inspection.
- **Cold-Start Evasion:** An adversary attempting immediate hostile egress on a brand-new agent before baseline warm-up was caught on **Call #1** (Risk: 0.85, Blocked) by the pre-baseline rule floor.
