import asyncio

from cerberus.proxy.forwarder import UpstreamMCPForwarder


def test_forwarder_error_handling():
    async def _run():
        f = UpstreamMCPForwarder()
        res = await f.forward_call("http://invalid-srv:8080", "tools/call", {})
        assert "error" in res

    asyncio.run(_run())
