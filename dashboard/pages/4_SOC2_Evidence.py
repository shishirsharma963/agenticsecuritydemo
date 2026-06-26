import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agentic_security import soc2  # noqa: E402

st.title("4 · SOC 2 Evidence Map")
st.caption("SOC 2 is not paperwork. It is proof that the control operated.")

st.subheader("🔴 Without a control")
st.error(soc2.bad_state_summary())

st.subheader("🟢 Control → owner → system → evidence")
cov = soc2.coverage()
c1, c2, c3 = st.columns(3)
c1.metric("Controls mapped", cov["controls"])
c2.metric("Continuous evidence", f"{cov['automation_pct']}%")
c3.metric("Manual", cov["manual"])

st.dataframe(
    [{"control": c.id, "name": c.name, "owner": c.owner, "system": c.system,
      "evidence": c.evidence, "cadence": c.cadence,
      "automated": "✅" if c.automated else "-"}
     for c in soc2.CONTROLS],
    hide_index=True, use_container_width=True,
)
