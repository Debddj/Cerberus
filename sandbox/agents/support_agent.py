import asyncio
import httpx

class SupportAgentSimulator:
    """Simulates a customer support ticket agent reading tickets and responding."""
    def __init__(self, proxy_url: str = "http://localhost:8000/mcp"):
        self.proxy_url = proxy_url

    async def run_task(self):
        sequence = [
            ("search_tickets", {"query": "status:open"}),
            ("read_ticket", {"id": "T-1002"}),
            ("send_email", {"to": "user@example.com", "subject": "Ticket update"}),
        ]
        async with httpx.AsyncClient() as client:
            for tool, params in sequence:
                await client.post(self.proxy_url, json={"method": "tools/call", "params": {"name": tool, "arguments": params}})
