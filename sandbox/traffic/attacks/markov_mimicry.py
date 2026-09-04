from cerberus.proxy.models import ToolCallEvent


def get_mimicry_sequence(session_id="attack-mimic-01", agent_id="coding-01") -> list[ToolCallEvent]:
    # Normal tool transition sequence for coding agent, but with hostile payload content
    return [
        ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name="read_file",
            tool_server="file-server",
            parameters={"path": "src/main.py"},
        ),
        ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name="write_file",
            tool_server="file-server",
            parameters={"path": "src/main.py", "exploit": True},
        ),
        ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            tool_name="run_tests",
            tool_server="file-server",
            parameters={"suite": "backdoor"},
        ),
    ]
