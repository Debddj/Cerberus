import streamlit as st

st.header("Least-Privilege Policy Approval Gate")

st.markdown("""
Review auto-synthesized Rego policies generated from stabilized agent baselines.
Policies remain in **Pending Review** until explicit human authorization is granted.
""")

col1, col2 = st.columns([3, 1])
with col1:
    st.subheader("Pending Policy: agent_triage_02.rego")
    st.code(
        """
package cerberus.agent.agent_triage_02
default allow = true

allowed_tools = {
    "fetch_inbox",
    "read_email",
    "scrape_url",
    "send_reply"
}

deny {
    not input.tool_name in allowed_tools
}
""",
        language="rego",
    )

with col2:
    st.write("Actions:")
    if st.button("✅ Approve Policy"):
        st.success("Policy approved and moved to active OPA distribution!")
    if st.button("❌ Reject"):
        st.warning("Policy rejected.")
