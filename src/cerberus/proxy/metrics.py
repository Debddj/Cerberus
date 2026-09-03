from prometheus_client import Counter, Histogram, Gauge, generate_latest

REQUEST_COUNT = Counter(
    "cerberus_proxy_requests_total",
    "Total tool call requests intercepted",
    ["tool_name", "decision"]
)

REQUEST_LATENCY = Histogram(
    "cerberus_proxy_latency_seconds",
    "Latency added by Cerberus interception pipeline",
    buckets=[0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500]
)

ACTIVE_QUARANTINES = Gauge(
    "cerberus_active_quarantines",
    "Total currently quarantined agent sessions"
)

def get_metrics_payload() -> bytes:
    return generate_latest()
