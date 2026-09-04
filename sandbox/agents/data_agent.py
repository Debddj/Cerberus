import httpx


class DataAgentSimulator:
    """Simulates a database analytics agent executing queries and exporting summaries."""

    def __init__(self, proxy_url: str = "http://localhost:8000/mcp"):
        self.proxy_url = proxy_url

    async def run_task(self):
        sequence = [
            ("query_db", {"sql": "SELECT count(*) FROM orders"}),
            ("query_db", {"sql": "SELECT avg(amount) FROM orders"}),
            ("read_file", {"path": "config/schema.json"}),
        ]
        async with httpx.AsyncClient() as client:
            for tool, params in sequence:
                await client.post(
                    self.proxy_url,
                    json={"method": "tools/call", "params": {"name": tool, "arguments": params}},
                )
