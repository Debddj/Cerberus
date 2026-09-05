import os
from pathlib import Path

import streamlit as st

from cerberus.policy.synthesizer import PolicySynthesizer

st.header("⚖️ OPA Policy Engine & Closed-Loop Approval Gate")
st.markdown("""
Manage base declarative Rego guardrails and review auto-synthesized least-privilege policies.
All auto-generated policies remain **Pending** until an authorized operator approves or rejects them.
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
    st.subheader("Human Approval Gate: Pending Auto-Synthesized Policies")
    st.markdown("""
    When an anomaly is blocked or an agent's behavioral profile reaches **Warm** status,
    Cerberus automatically synthesizes defensive Rego rules to lock down permissions.
    """)

    synthesizer = PolicySynthesizer(output_dir="policies/generated")
    pending_policies = synthesizer.list_pending_policies()

    if not pending_policies:
        st.success(
            "🎉 All auto-synthesized policies reviewed. No pending candidate rules awaiting operator approval."
        )
    else:
        st.write(f"**{len(pending_policies)} Candidate Policies Awaiting Operator Review:**")
        for pol in pending_policies:
            pol_id = pol.get("policy_id", "unknown")
            agent_id = pol.get("agent_id", "unknown")
            tool_name = pol.get("tool_name", "unknown")
            risk_score = pol.get("risk_score", 0.0)
            created_at = pol.get("created_at", "N/A")
            rego_path = pol.get("rego_path", "")

            with st.expander(
                f"🛡️ Policy {pol_id} | Agent: `{agent_id}` | Tool: `{tool_name}` (Risk: {risk_score:.2f})",
                expanded=True,
            ):
                col_meta1, col_meta2 = st.columns(2)
                col_meta1.markdown(f"**Target Agent:** `{agent_id}`\n**Tool:** `{tool_name}`")
                col_meta2.markdown(
                    f"**Synthesized At:** `{created_at}`\n**Risk Score:** `{risk_score:.2f}`"
                )

                # Display rego code
                if rego_path and os.path.exists(rego_path):
                    with open(rego_path, "r", encoding="utf-8") as rf:
                        rego_code = rf.read()
                    st.code(rego_code, language="rego")
                else:
                    st.warning(f"Rego source file missing at {rego_path}")

                col_appr, col_rej, col_spacer = st.columns([2, 2, 6])
                if col_appr.button(
                    "✅ Approve Policy", key=f"appr_{pol_id}", use_container_width=True
                ):
                    ok = synthesizer.approve_policy(pol_id)
                    if ok:
                        st.success(f"Policy {pol_id} approved and marked active!")
                        st.rerun()
                    else:
                        st.error(f"Failed to approve policy {pol_id}")

                if col_rej.button(
                    "❌ Reject Policy", key=f"rej_{pol_id}", use_container_width=True
                ):
                    ok = synthesizer.reject_policy(pol_id)
                    if ok:
                        st.warning(f"Policy {pol_id} rejected and archived.")
                        st.rerun()
                    else:
                        st.error(f"Failed to reject policy {pol_id}")
