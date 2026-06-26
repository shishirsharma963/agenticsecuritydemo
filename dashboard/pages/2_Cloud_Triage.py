import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agentic_security import triage  # noqa: E402

st.title("2 · Cloud Finding Triage")
st.caption("A few hundred findings are not a few hundred equal problems.")

findings = triage.load_findings()
paths = [f for f in findings if f.is_attack_path()]

c1, c2, c3 = st.columns(3)
c1.metric("Total findings", len(findings))
c2.metric("Real attack paths", len(paths))
c3.metric("Unassigned owners", sum(1 for f in findings if f.owner == "unassigned"))

st.divider()
bad_col, good_col = st.columns(2)

with bad_col:
    st.subheader("🔴 Sorted by vendor severity")
    st.caption("The few that matter are scattered through the list.")
    st.dataframe(
        [{"id": f.id, "vendor": f.vendor_severity, "title": f.title[:48]}
         for f in triage.vendor_view(findings)[:15]],
        hide_index=True, use_container_width=True,
    )

with good_col:
    st.subheader("🟢 Sorted by risk (toxic combinations first)")
    st.caption("Attack paths on top, each with an owner to route to.")
    st.dataframe(
        [{"score": f.risk_score(),
          "band": "ATTACK-PATH" if f.is_attack_path() else f.risk_band(),
          "id": f.id, "owner": f.owner,
          "factors": ", ".join(f.factors())}
         for f in triage.risk_view(findings)[:15]],
        hide_index=True, use_container_width=True,
    )

st.divider()
st.markdown("**Scoring weights**")
st.table([{"factor": k, "points": v} for k, v in triage.WEIGHTS.items()])
