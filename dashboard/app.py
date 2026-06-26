"""Agentic Security Demo console, optional Streamlit dashboard.

    pip install -r dashboard/requirements.txt
    streamlit run dashboard/app.py

The pages in the sidebar map to the same domains as `demo.py`, reusing the
same core modules in ../agentic_security. Synthetic data only.
"""

import sys
from pathlib import Path

import streamlit as st

# Make the agentic_security package importable regardless of where streamlit is launched.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

st.set_page_config(page_title="Agentic Security Demo Console", page_icon="🛡️", layout="wide")

st.title("🛡️ Agentic Security Demo Console")
st.caption(
    "Turning security tools into operating controls. Synthetic data, inspired by "
    "a security-engineering role, not based on any real company's environment."
)

st.markdown(
    """
This is a **mock prototype**. It shows the difference between a startup that
*bought* tools and one that turned them into **controls that produce evidence**.

**One operating pattern across all four tabs:**
classify the risk → assign an owner → enforce a control → produce evidence →
escalate the exception.

Use the sidebar:

| Tab | Shows |
|---|---|
| **AI Governance** | A prompt guardrail: a risky prompt, bad vs good |
| **Cloud finding triage** | findings re-ranked by toxic combination, not vendor severity |
| **Incident Response** | A declared incident with roles, timeline, and evidence |
| **SOC 2 Evidence** | Control → owner → system → evidence map |
"""
)
