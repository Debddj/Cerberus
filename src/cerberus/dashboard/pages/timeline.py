import pandas as pd
import plotly.express as px
import streamlit as st

from cerberus.dashboard.components.risk_chart import create_risk_gauge

st.header("📈 Session Risk Timeline")
st.markdown(
    "Visualize behavioral drift progression and anomaly escalation across session tool calls."
)

scenario = st.selectbox(
    "Select Incident Scenario to Chart:",
    [
        "Toxic Flow (Prompt Injection -> Data Exfil)",
        "Slow-Drip Exfiltration (15-Step Low-Volume Egress)",
        "Privilege Escalation (Out-of-Scope Admin Action)",
        "Normal Coding Session (Clean Baseline)",
    ],
)

if "Toxic Flow" in scenario:
    steps = [1, 2, 3]
    scores = [0.10, 0.45, 0.95]
    tools = ["read_public_issue", "read_private_repo", "http_post"]
    factors = [
        "Normal public data reading",
        "Elevated sensitivity: Private repository accessed",
        "CRITICAL: Read private data followed immediately by external egress to novel domain",
    ]
elif "Slow-Drip" in scenario:
    steps = list(range(1, 16))
    scores = [min(0.20 + 0.04 * i if i < 9 else 0.75, 0.85) for i in range(15)]
    tools = [f"http_post (chunk {i + 1})" for i in range(15)]
    factors = [
        "Normal chunk payload" if i < 9 else "Cumulative egress volume exceeded safety threshold"
        for i in range(15)
    ]
elif "Privilege" in scenario:
    steps = [1]
    scores = [0.90]
    tools = ["admin_drop_database"]
    factors = ["Administrative tool invoked outside declared permission scope"]
else:
    steps = [1, 2, 3, 4, 5, 6]
    scores = [0.05, 0.08, 0.06, 0.12, 0.09, 0.07]
    tools = ["read_file", "read_file", "search_code", "write_file", "run_tests", "read_file"]
    factors = ["Conforms to established coding agent baseline" for _ in range(6)]

df = pd.DataFrame(
    {
        "Call Step": steps,
        "Risk Score": scores,
        "Tool Name": tools,
        "Factor Explanation": factors,
    }
)

fig = px.line(
    df,
    x="Call Step",
    y="Risk Score",
    markers=True,
    text="Tool Name",
    title=f"Risk Score Trajectory — {scenario}",
    range_y=[0.0, 1.05],
)
fig.add_hline(
    y=0.40, line_dash="dot", line_color="goldenrod", annotation_text="Flag Threshold (0.40)"
)
fig.add_hline(
    y=0.70, line_dash="dash", line_color="darkorange", annotation_text="Block Threshold (0.70)"
)
fig.add_hline(
    y=0.90, line_dash="solid", line_color="crimson", annotation_text="Quarantine Threshold (0.90)"
)

st.plotly_chart(fig, use_container_width=True)

# Gauge and Factors breakdown
col_gauge, col_details = st.columns([1, 2])
with col_gauge:
    peak = max(scores)
    st.plotly_chart(create_risk_gauge(peak), use_container_width=True)

with col_details:
    st.subheader("Contributing Risk Factors")
    st.dataframe(
        df[["Call Step", "Tool Name", "Risk Score", "Factor Explanation"]], use_container_width=True
    )
