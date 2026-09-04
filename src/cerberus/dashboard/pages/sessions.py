import pandas as pd
import streamlit as st

st.header("Live Agent Sessions")

# Placeholder demo data
data = [
    {
        "Session ID": "sess-8f12",
        "Agent Archetype": "Coding Agent",
        "Calls": 42,
        "Max Risk": 0.18,
        "Status": "Normal",
    },
    {
        "Session ID": "sess-9a31",
        "Agent Archetype": "Triage Agent",
        "Calls": 87,
        "Max Risk": 0.44,
        "Status": "Flagged",
    },
    {
        "Session ID": "sess-c44d",
        "Agent Archetype": "Data Analysis",
        "Calls": 23,
        "Max Risk": 0.94,
        "Status": "Quarantined",
    },
]
df = pd.DataFrame(data)

st.dataframe(df, use_container_width=True)
