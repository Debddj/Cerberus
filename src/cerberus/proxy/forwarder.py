import logging
from typing import Any

import httpx

logger = logging.getLogger("cerberus.forwarder")


class UpstreamMCPForwarder:
    """Transparently dispatches approved tool calls to backend MCP servers."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def forward_call(
        self, server_url: str, method: str, params: dict[str, Any], request_id: Any = 1
    ) -> dict[str, Any]:
        try:
            resp = await self.client.post(
                server_url,
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to forward call to {server_url}: {e}")
            return {"error": {"code": -32000, "message": f"Upstream error: {e!s}"}}

    async def close(self):
        """Gracefully close the underlying httpx client."""
        await self.client.aclose()
