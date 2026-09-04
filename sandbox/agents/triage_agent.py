import httpx


class TriageAgentSimulator:
    """Simulates a high-exposure web research / inbox triage agent handling untrusted content."""

    def __init__(self, proxy_url: str = "http://localhost:8000/mcp"):
        self.proxy_url = proxy_url

    async def run_task(self):
        sequence = [
            ("fetch_inbox", {"folder": "INBOX"}),
            ("read_email", {"id": "MSG-908"}),
            ("scrape_url", {"url": "https://public-issue.example.org"}),
            ("send_reply", {"to": "author@example.org", "body": "Analyzed issue"}),
        ]
        async with httpx.AsyncClient() as client:
            for tool, params in sequence:
                await client.post(
                    self.proxy_url,
                    json={"method": "tools/call", "params": {"name": tool, "arguments": params}},
                )
