from fastapi import FastAPI, Response, Request, status
from cerberus.config import settings
from cerberus.proxy.metrics import get_metrics_payload, REQUEST_COUNT, REQUEST_LATENCY
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cerberus.proxy")

app = FastAPI(
    title="Cerberus MCP Firewall",
    description="A runtime behavioral firewall for MCP-based AI agents",
    version="0.1.0"
)

@app.get("/healthz")
async def health_check():
    return {
        "status": "healthy",
        "mode": settings.mode,
        "opa_url": settings.opa_url,
        "fail_closed": settings.fail_closed
    }

@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics_payload(), media_type="text/plain; version=0.0.4")

@app.post("/mcp")
async def mcp_proxy_gateway(request: Request):
    start_time = time.perf_counter()
    body = await request.json()
    
    # Process through pipeline (mock/scaffolded for initial handshake)
    duration = time.perf_counter() - start_time
    REQUEST_LATENCY.observe(duration)
    REQUEST_COUNT.labels(tool_name="sample_tool", decision="allow").inc()
    
    return {
        "jsonrpc": "2.0",
        "id": body.get("id", 1),
        "result": {"status": "proxied", "cerberus_decision": "allow"}
    }
