import random

from cerberus.proxy.models import ToolCallEvent


def generate_triage_stream(agent_id="triage-01", count=100) -> list[ToolCallEvent]:
    events = []
    tools = ["fetch_inbox", "read_email", "scrape_url", "send_reply"]
    for i in range(count):
        t = random.choice(tools)
        events.append(
            ToolCallEvent(
                session_id=f"sess-triage-{i // 10}",
                agent_id=agent_id,
                tool_name=t,
                tool_server="inbox-server",
                parameters={"url": f"https://doc-{i}.org"},
                sequence_position=i % 10,
            )
        )
    return events
