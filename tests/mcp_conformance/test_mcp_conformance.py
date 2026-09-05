from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp import types

from cerberus.proxy.models import EventDecision, ToolCallEvent
from cerberus.proxy.stdio_server import CerberusStdioProxy


@pytest.mark.asyncio
async def test_mcp_stdio_proxy_initialization():
    proxy = CerberusStdioProxy(command="dummy_server", args=["--flag"])
    assert proxy.server.name == "cerberus-stdio-firewall"
    assert proxy.agent_id == "agent-stdio"
    assert proxy.session_id == "session-stdio"


@pytest.mark.asyncio
async def test_mcp_stdio_proxy_call_tool_allow():
    proxy = CerberusStdioProxy(command="echo_server")

    # Mock engine.process_tool_call to return ALLOW
    mock_event = ToolCallEvent(
        session_id="session-stdio",
        agent_id="agent-stdio",
        tool_name="echo",
        tool_server="stdio:echo_server",
        parameters={"msg": "hello"},
        decision=EventDecision.ALLOW,
    )
    proxy.engine.process_tool_call = AsyncMock(
        return_value=(mock_event, {"blocked": False, "status": "executed"})
    )

    # Mock upstream session
    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()
    mock_call_res = MagicMock()
    mock_call_res.content = [types.TextContent(type="text", text="hello from upstream")]
    mock_session.call_tool = AsyncMock(return_value=mock_call_res)

    with patch("cerberus.proxy.stdio_server.stdio_client") as mock_stdio:
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mock_ctx.__aexit__.return_value = None
        mock_stdio.return_value = mock_ctx

        with patch("cerberus.proxy.stdio_server.ClientSession") as mock_session_cls:
            mock_sess_ctx = AsyncMock()
            mock_sess_ctx.__aenter__.return_value = mock_session
            mock_sess_ctx.__aexit__.return_value = None
            mock_session_cls.return_value = mock_sess_ctx

            res = await proxy._proxy_call_tool("echo", {"msg": "hello"})
            assert len(res) == 1
            assert res[0].text == "hello from upstream"


@pytest.mark.asyncio
async def test_mcp_stdio_proxy_call_tool_block():
    proxy = CerberusStdioProxy(command="echo_server")

    # Mock engine.process_tool_call to return BLOCK
    mock_event = ToolCallEvent(
        session_id="session-stdio",
        agent_id="agent-stdio",
        tool_name="drop_table",
        tool_server="stdio:echo_server",
        parameters={"table": "users"},
        decision=EventDecision.BLOCK,
        decision_reason="Destructive operation blocked",
        risk_score=0.95,
    )
    proxy.engine.process_tool_call = AsyncMock(
        return_value=(
            mock_event,
            {
                "blocked": True,
                "reason": "Destructive operation blocked",
                "risk_score": 0.95,
            },
        )
    )

    res = await proxy._proxy_call_tool("drop_table", {"table": "users"})
    assert len(res) == 1
    assert "[CERBERUS FIREWALL BLOCKED]" in res[0].text
    assert "Destructive operation blocked" in res[0].text
    assert "0.95" in res[0].text
