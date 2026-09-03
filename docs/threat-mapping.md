# Threat Taxonomy Mapping

Cerberus directly maps its detection and interception capabilities against industry standards.

## OWASP Top 10 for Agentic Applications (2026)
- **ASI01: Agent Goal Hijack:** Detected via behavioral drift. An agent switching from coding to credential scraping causes rapid Markov surprise spikes.
- **ASI02: Tool Misuse & Exploitation:** Caught by parameter entropy checks and payload size thresholds.
- **ASI03: Identity & Privilege Abuse:** Out-of-scope tool calls rejected by scope analyzer and auto-synthesized least-privilege Rego policies.
- **ASI04: Agentic Supply Chain Vulnerabilities:** Tool poisoning and rug-pull modifications caught by SHA-256 schema pinning.
- **ASI10: Rogue Agents:** Sessions showing sustained anomaly scores trigger session quarantine mid-attack.

## OWASP MCP Top 10 & NSA Guidance
- **Rug Pull Attack:** Server dynamically modifies tool definitions after initial trust establishment. Blocked by Schema Pinner.
- **Tool Shadowing:** Lookalike tools from untrusted servers detected by Shadow Detector.
- **Dynamic Inversion Risks (NSA CSI May 2026):** Addressed via runtime transparent interception and non-repudiable audit logging.
