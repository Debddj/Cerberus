from cerberus.proxy.models import ToolCallEvent


def get_privilege_escalation_event(
    session_id="attack-priv-01", agent_id="support-01"
) -> ToolCallEvent:
    return ToolCallEvent(
        session_id=session_id,
        agent_id=agent_id,
        tool_name="admin_drop_database",
        tool_server="db-server",
        parameters={"table": "users"},
    )
