import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agentic_security import incident  # noqa: E402

st.title("3 · Security Incident")
st.caption("The incident record is the operating evidence.")

st.subheader("🔴 Without a control")
st.error(incident.bad_state_summary())

st.subheader("🟢 Declared incident")
inc = incident.declare_vp_laptop_incident()
rec = inc.to_record()

c1, c2, c3 = st.columns(3)
c1.metric("Incident", rec["id"])
c2.metric("Severity", rec["severity"])
c3.metric("Status", rec["status"])
st.caption(rec["severity_meaning"])

st.markdown("**Roles**")
st.table([{"role": k, "assigned": v} for k, v in rec["roles"].items()])

st.markdown("**Timeline (every step produces evidence)**")
st.dataframe(
    [{"time": t["at"][11:19], "action": t["action"], "evidence": t["evidence"]}
     for t in rec["timeline"]],
    hide_index=True, use_container_width=True,
)

st.markdown("**Postmortem actions**")
for a in rec["postmortem_actions"]:
    st.write(f"- {a}")

st.info("Evidence for: " + ", ".join(rec["evidence_for"]))
