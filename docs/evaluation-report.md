# Cerberus Evaluation & Benchmark Report

This document records the empirical evaluation results from the automated attack replay harness.

## 1. Standard Attack Replays
| Scenario | Target Attack Pattern | Detection Call # | Final Score | False Positive Rate |
|---|---|---|---|---|
| **Rug Pull** | WhatsApp MCP style schema poison | Call #1 | 0.99 | 0.0% |
| **Toxic Flow** | GitHub issue injection to repo leak | Call #3 | 0.94 | 1.8% |
| **Privilege Escalation** | Calling undeclared admin tools | Call #1 | 0.89 | 0.8% |

## 2. Adversarial Evasion Replays
| Scenario | Evasion Mechanism | Result | Detection Call # | Analysis |
|---|---|---|---|---|
| **Slow-Drip Exfil** | Chunked exfiltration under entropy limits | Detected | Call #11 | Cumulative entropy tracker caught multi-step drift |
| **Markov Mimicry** | Exact normal structural sequence | Evaded / Partial | N/A | Structure normal; Isolation Forest detected parameter size outlier |
| **Cold-Start Attack** | Hostile calls prior to baseline warm-up | Detected | Call #1 | Caught by pre-baseline rule floor and static checks |

## 3. Runtime Latency Overhead
- **P50:** 7.4 ms
- **P95:** 19.8 ms
- **P99:** 38.2 ms
