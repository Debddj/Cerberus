import streamlit as st

st.header("Baseline Health & Stability Rollback")

st.write("Manage per-agent behavioral snapshots and protect against boiling-frog poisoning.")

st.dataframe(
    [
        {
            "Agent ID": "coding-agent-01",
            "Active Snapshot": "snap_v4",
            "Observed Calls": 412,
            "Warm": True,
            "Flagged Excluded": 3,
            "Last Review": "2026-08-28",
        },
        {
            "Agent ID": "triage-agent-01",
            "Active Snapshot": "snap_v2",
            "Observed Calls": 184,
            "Warm": True,
            "Flagged Excluded": 1,
            "Last Review": "2026-09-01",
        },
        {
            "Agent ID": "data-agent-01",
            "Active Snapshot": "snap_v1",
            "Observed Calls": 46,
            "Warm": False,
            "Flagged Excluded": 0,
            "Last Review": "Never",
        },
    ],
    use_container_width=True,
)

if st.button("Rollback coding-agent-01 to snap_v3"):
    st.info("Rollback executed: coding-agent-01 restored to snapshot v3.")
