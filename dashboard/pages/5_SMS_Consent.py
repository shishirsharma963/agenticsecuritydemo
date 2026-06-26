import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agentic_security import consent  # noqa: E402

st.title("5 · TCPA SMS-Consent Guardrail")
st.caption("Outbound customer SMS: every send is a TCPA decision.")

reg = consent.load_registry()

hour = st.slider("Send time (UTC hour)", 0, 23, 13)
when = datetime(2026, 6, 22, hour, 0, tzinfo=timezone.utc)

st.subheader("🔴 Without a control")
st.error(consent.bad_state_summary())

st.subheader("🟢 Consent-gated send")
rows = []
cleared = 0
for cid, rec in reg.items():
    r = consent.evaluate_send(consent.SMSSend(cid, "Brand_X_Outreach", when), reg)
    cleared += r.allowed
    rows.append({"contact": rec.name, "consent": rec.consent, "tz": rec.timezone,
                 "decision": "✅ ALLOW" if r.allowed else "⛔ BLOCK",
                 "reason": r.reasons[-1]})

c1, c2 = st.columns(2)
c1.metric("Cleared to send", f"{cleared}/{len(reg)}")
c2.metric("Blocked", len(reg) - cleared)
st.dataframe(rows, hide_index=True, use_container_width=True)
st.caption("Quiet hours = 8am to 9pm local to each recipient. Move the slider to "
           "watch the West-coast recipients drop out early in the morning.")
