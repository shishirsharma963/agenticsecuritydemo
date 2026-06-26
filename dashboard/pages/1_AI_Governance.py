import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from agentic_security import governance as gov  # noqa: E402

st.title("1 · AI Prompt / Data Governance")
st.caption("Prompt guardrail: same prompt, two control states.")

destination = st.selectbox(
    "Destination AI tool",
    list(gov.APPROVED_TOOLS.keys()),
    index=list(gov.APPROVED_TOOLS).index("public-llm-chatbot"),
)
prompt = st.text_area("Prompt a developer is about to send", gov.SAMPLE_RISKY_PROMPT, height=200)

req = gov.AIRequest(
    prompt=prompt,
    actor_chain=[
        gov.AgentHop("alice.dev", "human", "debug a failed delivery"),
        gov.AgentHop("delivery", "delivery-agent", "diagnose delivery failure"),
        gov.AgentHop("retrieval", "retrieval-agent", "fetch the matching record"),
    ],
    destination=destination,
    cost_center="eng-platform",
)

bad_col, good_col = st.columns(2)

with bad_col:
    st.subheader("🔴 BAD: tools, no controls")
    res_bad = gov.process_request(req, mode="bad")
    st.error("Prompt forwarded raw. No classification, no identity, no audit.")
    st.code(res_bad.sanitized_prompt, language="text")
    st.metric("Spend (unattributed)", f"${res_bad.est_cost_usd}")

with good_col:
    st.subheader("🟢 GOOD: guardrail")
    res = gov.process_request(req, mode="good")
    if res.allowed:
        st.success("Allowed: sanitized and logged.")
    else:
        st.warning("Blocked / rerouted at the boundary.")

    st.markdown("**Detections**")
    st.table([{"data class": d.data_class.value, "confidence": d.confidence,
               "reason": d.reason} for d in res.detections] or [{"data class": "none"}])

    st.markdown("**Policy decisions**")
    st.table([{"action": d.action.value, "reason": d.reason} for d in res.decisions])

    st.markdown("**Sanitized prompt that would leave the boundary**")
    st.code(res.sanitized_prompt, language="text")

    st.markdown("**Actor chain (per-hop intent)**")
    st.write(" → ".join(res.audit_record["actor_chain"]))

    st.markdown("**Audit record (the evidence)**")
    st.json(res.audit_record)
