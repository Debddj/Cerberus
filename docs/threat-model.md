# Cerberus Meta-Security & Self-Defense Threat Model

Security monitoring systems are themselves prime targets for adversaries. Cerberus explicitly models and defends against three critical self-referential attacks:

## 1. Policy Engine Denial of Service / Crash
- **Attack:** An adversary purposefully overloads or crashes the OPA sidecar to force a fail-open state.
- **Defense:** Cerberus implements a strict **Fail-Closed default**. If OPA is unreachable, any call that triggers a static scanner rule or has a behavioral risk score >= 0.7 is unconditionally **BLOCKED**. Only known low-risk calls on warm baselines degrade to logging-only allow.

## 2. Audit Log as an Exfiltration Breach Vector
- **Attack:** Prompts, parameters, or responses containing API keys, passwords, or PII are logged in plaintext, turning Cerberus's audit log into a centralized repository of stolen secrets.
- **Defense:** Pre-persistence secret redaction. Regular expressions strip API tokens, RSA keys, and Bearer tokens before writing to disk. Persisted audit logs are encrypted at rest.

## 3. Baseline Poisoning ("Boiling Frog" Attacks)
- **Attack:** An adversary conducts very slow, subtle shifts in behavior over hundreds of calls to pollute the agent's baseline model, making the final exfiltration appear "normal".
- **Defense:**
  - **Versioned Snapshots:** Baselines are immutable snapshots, not unconstrained sliding windows.
  - **Stability Gating:** Any session containing a flagged or quarantined event is permanently excluded from baseline retraining.
  - **Human-in-the-Loop Review:** Periodic alerts flag baselines that have drifted significantly or have not been reviewed.
