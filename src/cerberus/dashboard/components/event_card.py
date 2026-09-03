def render_event_card(event_dict: dict) -> str:
    return f"""
    ### Event {event_dict.get('event_id', 'unknown')}
    - **Tool:** `{event_dict.get('tool_name')}` ({event_dict.get('tool_server')})
    - **Risk:** {event_dict.get('risk_score', 0.0):.2f}
    - **Decision:** **{event_dict.get('decision', 'ALLOW').upper()}**
    """
