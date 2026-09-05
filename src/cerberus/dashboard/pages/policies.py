from pathlib import Path

import streamlit as st

st.header("⚖️ OPA Policy Engine & Approval Gate")
st.markdown("""
Manage base declarative Rego guardrails and review auto-synthesized least-privilege policies.
All auto-generated policies remain **Pending** until an authorized operator approves them.
""")

tab_base, tab_auto = st.tabs(
    ["Active Base Rego Policies", "Auto-Synthesized Least-Privilege Policies"]
)

with tab_base:
    st.subheader("Base Declarative Policies")
    policy_dir = Path("policies/base")
    policy_files = list(policy_dir.glob("*.rego")) if policy_dir.exists() else []

    if policy_files:
        chosen_file = st.selectbox("Select Policy to view:", [f.name for f in policy_files])
        file_path = policy_dir / chosen_file
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        st.code(content, language="rego")
    else:
        st.info("No policy files discovered in policies/base.")

with tab_auto:
    st.subheader("Human Approval Gate: Pending Least-Privilege Policies")
    st.markdown("""
    When an agent's behavioral profile reaches **Warm** status (>=100 safe calls),
    Cerberus auto-synthesizes a least-privilege boundary locking the agent to observed tools and domains.
    """)

    sample_policy = """# AUTO-GENERATED LEAST-PRIVILEGE POLICY (Pending Human Approval)
package cerberus.agent.agent_coding_01

import rego.v1

default allow := false

allowed_tools := {
    "read_file",
    "write_file",
    "run_tests",
    "search_code"
}

allowed_destinations := {
    "github.com",
    "api.internal-ci.net"
}

allow if {
    input.tool_name in allowed_tools
    not input.destination_domain
}

allow if {
    input.tool_name in allowed_tools
    input.destination_domain in allowed_destinations
}
"""
    col_code, col_act = st.columns([3, 1])
    with col_code:
        st.code(sample_policy, language="rego")
    with col_act:
        st.write("Actions:")
        if st.button("✅ Approve Policy"):
            st.success("Policy approved! Promoted to active OPA distribution.")
        if st.button("❌ Reject Policy"):
            st.warning("Policy rejected. Baseline remains in observation mode.")
