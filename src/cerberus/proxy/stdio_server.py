"""MCP stdio proxy server powered by official MCP Python SDK.

Wraps child MCP server processes over stdio (Claude Desktop / Cursor pattern)
and intercepts tool discovery and tool executions using CerberusProxyEngine.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

from cerberus.proxy.models import EventDecision
from cerberus.proxy.server import CerberusProxyEngine

logger = logging.getLogger("cerberus.mcp_stdio")


class CerberusStdioProxy:
    """Bridges client <-> Cerberus <-> Upstream MCP Server over stdio."""

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        engine: CerberusProxyEngine | None = None,
        agent_id: str = "agent-stdio",
        session_id: str = "session-stdio",
    ):
        self.command = command
        self.args = args or []
        self.env = env
        self.engine = engine or CerberusProxyEngine()
        self.agent_id = agent_id
        self.session_id = session_id
        self.server = Server("cerberus-stdio-firewall")
        self._setup_server_handlers()

    def _setup_server_handlers(self):
        self.server.add_request_handler(
            "tools/list", types.PaginatedRequestParams, self._handle_list_tools
        )
        self.server.add_request_handler(
            "tools/call", types.CallToolRequestParams, self._handle_call_tool
        )

    async def _handle_list_tools(
        self, params: types.PaginatedRequestParams | None = None
    ) -> types.ListToolsResult:
        tools = await self._proxy_list_tools()
        return types.ListToolsResult(tools=tools)

    async def _handle_call_tool(self, params: types.CallToolRequestParams) -> types.CallToolResult:
        content = await self._proxy_call_tool(params.name, params.arguments or {})
        return types.CallToolResult(content=content)

    async def _proxy_list_tools(self) -> list[types.Tool]:
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env,
        )
        async with (
            stdio_client(server_params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools_res = await session.list_tools()
            server_id = f"stdio:{self.command}"
            for tool in tools_res.tools:
                schema_dict = getattr(tool, "inputSchema", getattr(tool, "input_schema", {}))
                if not isinstance(schema_dict, dict):
                    schema_dict = {}
                await self.engine.schema_pinner.verify_or_pin(
                    server_id, tool.name, tool.description or "", schema_dict
                )
            return tools_res.tools

    async def _proxy_call_tool(self, name: str, arguments: dict[str, Any]) -> list[Any]:
        server_id = f"stdio:{self.command}"

        # Intercept and score through Cerberus engine
        event, outcome = await self.engine.process_tool_call(
            session_id=self.session_id,
            agent_id=self.agent_id,
            tool_name=name,
            tool_server=server_id,
            parameters=arguments,
        )

        # Blocked by firewall
        if outcome.get("blocked") or event.decision in (
            EventDecision.BLOCK,
            EventDecision.QUARANTINE,
        ):
            reason = outcome.get("reason") or event.decision_reason or "Blocked by Cerberus policy"
            score = outcome.get("risk_score") or event.risk_score or 0.0
            error_msg = f"[CERBERUS FIREWALL BLOCKED] {reason} (Risk: {score:.2f})"
            return [types.TextContent(type="text", text=error_msg)]

        # Forward to upstream subprocess
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.env,
        )
        async with (
            stdio_client(server_params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            call_res = await session.call_tool(name, arguments)
            return list(call_res.content)

    async def run(self):
        await self.engine.initialize()
        async with stdio_server() as (read_stream, write_stream):
            init_options = self.server.create_initialization_options(
                notification_options=None,
                experimental_capabilities={},
            )
            await self.server.run(read_stream, write_stream, init_options)


async def run_stdio_proxy(command: str, args: list[str] | None = None):
    proxy = CerberusStdioProxy(command=command, args=args)
    await proxy.run()
