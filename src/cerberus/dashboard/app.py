import streamlit as st

st.set_page_config(
    page_title="Cerberus MCP Behavioral Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ Cerberus Security Operations Center")
st.markdown("""
Welcome to the Cerberus runtime behavioral firewall control plane.
Use the sidebar navigation to inspect live sessions, explore reconstructed attack chains, review auto-synthesized policies, and manage agent behavioral baselines.
""")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Active Agents", "4", "+1")
col2.metric("Total Intercepts", "1,248", "99.8% allowed")
col3.metric("Flagged / Quarantined", "14", "2 active")
col4.metric("P95 Latency", "18.4 ms", "-2.1 ms")

st.info("💡 Running in **ENFORCE** mode with Fail-Closed policy defaults.")
