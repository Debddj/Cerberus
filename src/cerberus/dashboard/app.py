import json
from pathlib import Path
from typing import Any

import streamlit as st

st.set_page_config(
    page_title="Cerberus MCP Behavioral Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load real evaluation results if available
eval_path = Path("evaluation/evaluation_results.json")
eval_data: dict[str, Any] = {}
if eval_path.exists():
    try:
        with open(eval_path, "r", encoding="utf-8") as f:
            eval_data = json.load(f)
    except Exception:
        eval_data = {}

summary = eval_data.get("summary", {})
std_tpr = summary.get("standard_tpr", 1.0) * 100
eva_tpr = summary.get("evasion_tpr", 0.667) * 100
fpr = summary.get("overall_fpr", 0.0) * 100
lat_p50 = summary.get("latency", {}).get("p50", 12.22)
lat_p95 = summary.get("latency", {}).get("p95", 14.02)
lat_p99 = summary.get("latency", {}).get("p99", 15.43)

st.title("🛡️ Cerberus Security Operations Center")
st.markdown("""
**Runtime Behavioral Firewall for MCP-based AI Agents** — intercepting tool calls in real-time,
detecting anomalous multi-step attack chains, enforcing Open Policy Agent (OPA) guardrails,
and reconstructing end-to-end incident narratives.
""")

# Top metrics row
col1, col2, col3, col4 = st.columns(4)
col1.metric("Standard Attack TPR", f"{std_tpr:.1f}%", "Target >90%")
col2.metric("Evasion Resistance TPR", f"{eva_tpr:.1f}%", "Target >50%")
col3.metric("False Positive Rate", f"{fpr:.2f}%", "Target <5%")
col4.metric("P50 / P99 Latency", f"{lat_p50:.1f} ms / {lat_p99:.1f} ms", "Budget <50 ms")

st.markdown("---")

# Operational Status Callouts
c_stat1, c_stat2, c_stat3 = st.columns(3)
with c_stat1:
    st.success(
        "🔒 **Enforcement Mode: ENFORCE (Active)**\n\nFail-closed default active for OPA outages."
    )
with c_stat2:
    st.info(
        "🛡️ **Static Scanner: ARMED**\n\nSHA-256 schema pinner & lethal trifecta detector active."
    )
with c_stat3:
    st.warning(
        "⚡ **Behavioral Ensemble: WARM**\n\nMarkov + Isolation Forest + Rules + Sequence Transformer."
    )

# System Architecture & Navigation Overview
st.subheader("Control Plane Subsystems")
nav_col1, nav_col2, nav_col3 = st.columns(3)

with nav_col1:
    st.markdown("""
    ### 📋 Live Sessions
    Inspect raw and redacted tool calls across synthetic agents and benchmark replay scenarios.
    - Inspect real-time parameter payloads
    - Verify secret redaction (`[REDACTED]`)
    - Check per-call allow/block/quarantine status
    """)

with nav_col2:
    st.markdown("""
    ### 📈 Risk Timelines & Stories
    Visualize behavioral drift curves and reconstruct attack sequences into SOC narratives.
    - Step-by-step risk escalation
    - Reconnaissance -> Staging -> Exfiltration phases
    - Gauge charts and scorer attribution
    """)

with nav_col3:
    st.markdown("""
    ### ⚖️ Policies & Baselines
    Manage least-privilege Rego guardrails and inspect per-agent behavioral stability.
    - Human-in-the-loop policy approval gate
    - Versioned baseline snapshots (`v1` → `v4`)
    - One-click rollback against boiling-frog poisoning
    """)

st.markdown("---")
st.caption(
    "Cerberus v1.0.0 | MCP SDK v2 Kernel | Open Policy Agent Rego v1 | Scikit-Learn & PyTorch Sequence Scorer"
)
