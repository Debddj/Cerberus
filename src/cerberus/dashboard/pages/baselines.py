import streamlit as st

st.header("🧬 Baseline Health & Anti-Poisoning Rollback")
st.markdown("""
Cerberus maintains **versioned, immutable snapshots** of agent behavior.
Any session containing flagged or quarantined calls is **stability-gated** (excluded from retraining)
to defend against *boiling-frog* baseline poisoning attacks.
""")

st.subheader("Per-Agent Behavioral Baselines")

baselines_data = [
    {
        "Agent ID": "coding-agent-01",
        "Archetype": "Coding Agent",
        "Active Snapshot": "snap_v4 (Active)",
        "Observed Calls": 412,
        "Status": "Warm (Trusted)",
        "Flagged Excluded": 3,
        "Known Tools": "read_file, write_file, search_code, run_tests",
    },
    {
        "Agent ID": "data-agent-01",
        "Archetype": "Data Analysis",
        "Active Snapshot": "snap_v3 (Active)",
        "Observed Calls": 288,
        "Status": "Warm (Trusted)",
        "Flagged Excluded": 2,
        "Known Tools": "query_db, read_file, export_report",
    },
    {
        "Agent ID": "support-agent-01",
        "Archetype": "Customer Support",
        "Active Snapshot": "snap_v2 (Active)",
        "Observed Calls": 195,
        "Status": "Warm (Trusted)",
        "Flagged Excluded": 1,
        "Known Tools": "search_tickets, read_ticket, send_email, update_ticket",
    },
    {
        "Agent ID": "triage-agent-01",
        "Archetype": "Web Triage",
        "Active Snapshot": "snap_v2 (Active)",
        "Observed Calls": 154,
        "Status": "Warm (Trusted)",
        "Flagged Excluded": 4,
        "Known Tools": "fetch_inbox, read_email, scrape_url, send_reply",
    },
]

st.dataframe(baselines_data, use_container_width=True)

st.markdown("---")
st.subheader("⏪ Instant Baseline Rollback")
st.markdown(
    "If a baseline is suspected of contamination or drift, roll back to a known-clean immutable snapshot:"
)

col_agent, col_snap, col_btn = st.columns([2, 2, 1])
with col_agent:
    sel_agent = st.selectbox("Select Agent:", [d["Agent ID"] for d in baselines_data])
with col_snap:
    sel_snap = st.selectbox(
        "Rollback Target Snapshot:",
        ["snap_v3 (2026-08-30)", "snap_v2 (2026-08-25)", "snap_v1 (Initial)"],
    )
with col_btn:
    st.write("")
    st.write("")
    if st.button("Execute Rollback"):
        st.success(f"Successfully rolled back {sel_agent} to {sel_snap}!")
