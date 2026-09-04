import random

from cerberus.proxy.models import ToolCallEvent


def generate_coding_stream(agent_id="coding-01", count=100) -> list[ToolCallEvent]:
    events = []
    tools = ["read_file", "write_file", "search_code", "run_tests"]
    for i in range(count):
        t = random.choice(tools)
        events.append(
            ToolCallEvent(
                session_id=f"sess-coding-{i // 10}",
                agent_id=agent_id,
                tool_name=t,
                tool_server="file-server",
                parameters={"path": f"src/{t}.py"},
                sequence_position=i % 10,
            )
        )
    return events
