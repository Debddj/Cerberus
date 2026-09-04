import httpx


class CodingAgentSimulator:
    """Simulates a developer assistant agent reading files, running tests, writing code."""

    def __init__(self, proxy_url: str = "http://localhost:8000/mcp"):
        self.proxy_url = proxy_url

    async def run_task(self):
        sequence = [
            ("read_file", {"path": "src/main.py"}),
            ("read_file", {"path": "tests/test_main.py"}),
            ("write_file", {"path": "src/main.py", "content": "print('fixed')"}),
            ("run_tests", {"suite": "unit"}),
        ]
        async with httpx.AsyncClient() as client:
            for tool, params in sequence:
                await client.post(
                    self.proxy_url,
                    json={"method": "tools/call", "params": {"name": tool, "arguments": params}},
                )
