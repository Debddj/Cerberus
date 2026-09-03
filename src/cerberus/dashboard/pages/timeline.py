import streamlit as st
import plotly.express as px
import pandas as pd

st.header("Session Risk Timeline")

# Sample timeline plot
df = pd.DataFrame({
    "Tool Call Step": [1, 2, 3, 4, 5, 6],
    "Risk Score": [0.05, 0.10, 0.22, 0.48, 0.81, 0.95],
    "Tool Name": ["read_file", "list_dir", "read_file", "query_db", "read_file", "http_post"]
})

fig = px.line(df, x="Tool Call Step", y="Risk Score", markers=True, text="Tool Name", title="Attack Chain Progression (Session sess-c44d)")
fig.add_hline(y=0.70, line_dash="dash", line_color="orange", annotation_text="Block Threshold")
fig.add_hline(y=0.90, line_dash="dash", line_color="red", annotation_text="Quarantine Threshold")
st.plotly_chart(fig, use_container_width=True)
