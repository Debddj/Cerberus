import random

from cerberus.proxy.models import ToolCallEvent


def generate_support_stream(agent_id="support-01", count=100) -> list[ToolCallEvent]:
    events = []
    tools = ["search_tickets", "read_ticket", "send_email", "update_ticket"]
    for i in range(count):
        t = random.choice(tools)
        events.append(
            ToolCallEvent(
                session_id=f"sess-supp-{i // 10}",
                agent_id=agent_id,
                tool_name=t,
                tool_server="webhook-server",
                parameters={"id": f"ticket_{i}"},
                sequence_position=i % 10,
            )
        )
    return events
