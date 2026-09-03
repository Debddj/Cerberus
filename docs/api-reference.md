# Cerberus API Reference

## Interception Proxy Endpoints

### 1. JSON-RPC MCP Gateway
- **URL:** `POST /mcp`
- **Description:** Transparent MCP forwarder and inspection gateway.
- **Payload:** Standard MCP JSON-RPC frame (`tools/list`, `tools/call`).

### 2. Metrics Telemetry
- **URL:** `GET /metrics`
- **Description:** Prometheus metrics endpoint exposing:
  - `cerberus_proxy_requests_total`: Total intercepted requests by decision.
  - `cerberus_proxy_latency_seconds`: Latency distribution histogram.
  - `cerberus_active_quarantines`: Current quarantined sessions.

### 3. Health & Status
- **URL:** `GET /healthz`
- **Response:** `{"status": "healthy", "mode": "enforce", "opa_connected": true}`
