#!/usr/bin/env python3
"""Agentic Security Demo: one command, every domain, bad vs good.

    python3 demo.py

No services, no Docker, no API keys, no network. Synthetic data only. This does
not touch any real environment.
"""

from pathlib import Path

from datetime import date

from agentic_security import governance as gov
from agentic_security import triage, incident, soc2, scanner, consent, threatmodel, redteam
from agentic_security.appsec import pentest, dast, connectors, release_gate
from agentic_security.detection import autoresponse
from agentic_security.cloud import baseline

ROOT = Path(__file__).resolve().parent
BAR = "=" * 74
SUB = "-" * 74


def header(title: str) -> None:
    print(f"\n{BAR}\n  {title}\n{BAR}")


def bad(msg: str) -> None:
    print(f"  BAD   | {msg}")


def good(msg: str) -> None:
    print(f"  GOOD  | {msg}")


# --------------------------------------------------------------------------- #
def demo_governance() -> None:
    header("1. AI PROMPT / DATA GOVERNANCE")
    print("  A developer pastes a production error containing a card number, an")
    print("  account id, an internal note, and an AWS secret into an AI tool.")
    print("  Same prompt, two control states.\n")

    req = gov.sample_request(destination="chatgpt-consumer")

    res_bad = gov.process_request(req, mode="bad")
    bad(f"prompt forwarded raw to '{req.destination}' "
        f"({res_bad.est_tokens} tokens, ${res_bad.est_cost_usd}), "
        f"no classification, no identity, no audit, spend unattributed")

    res = gov.process_request(req, mode="good")
    print()
    good("detected: " + ", ".join(f"{d.data_class.value}({d.confidence})"
                                  for d in res.detections))
    for d in res.decisions:
        good(f"decision {d.action.value:7}- {d.reason}")
    print()
    good("sanitized prompt that would leave the boundary:")
    for line in res.sanitized_prompt.splitlines():
        print(f"        | {line}")
    print()
    good(f"actor chain: {' -> '.join(res.audit_record['actor_chain'])}")
    good(f"chain verified: {res.chain_verified} ({res.audit_record['chain_reason']}) "
         "- per-hop signed tokens, not just strings")
    good(f"allowed={res.allowed}  cost ${res.est_cost_usd} -> {res.audit_record['cost_center']}")
    good(f"vault holds re-identification map for {len(res.token_vault)} tokenized field(s)")
    good("one audit record emitted -> " + ", ".join(res.audit_record["evidence_for"]))

    # identity attack test: a forged chain is rejected even on an otherwise clean prompt
    forged = gov.AIRequest(
        prompt="Summarize this public press release.",
        actor_chain=[gov.AgentHop("dev", "human", "summarize")],
        destination="amazon-bedrock",
        chain_tokens=[gov.identity.mint_chain([("dev", "human", "summarize")])[0][:-2] + "zz"],
    )
    fr = gov.process_request(forged, mode="good")
    print()
    good(f"attack test, forged agent chain on a clean prompt: allowed={fr.allowed} "
         "(identity verification caught it)")


def demo_triage() -> None:
    header("2. AWS CLOUD FINDING TRIAGE")
    findings = triage.load_findings()
    paths = [f for f in findings if f.is_attack_path()]
    print(f"  {len(findings)} synthetic AWS Security Hub findings loaded. "
          f"{len(paths)} form a real attack path.\n")

    bad("top of the queue when you sort by vendor severity only:")
    for f in triage.vendor_view(findings)[:4]:
        print(f"        | {f.vendor_severity:8} {f.id}  {f.title[:46]}")
    print()
    good("top of the queue when you sort by risk (toxic combinations first):")
    for f in triage.risk_view(findings)[:5]:
        flag = "ATTACK-PATH" if f.is_attack_path() else f.risk_band()
        print(f"        | score {f.risk_score():3} [{flag:11}] {f.id}  owner={f.owner}")
        print(f"        |            factors: {', '.join(f.factors())}")
    print()
    good(f"same {len(findings)} findings, the {len(paths)} that can actually hurt "
         f"you are now on top, each with an owner to route to.")


def demo_incident() -> None:
    header("3. SECURITY INCIDENT  (AWS-native containment)")
    bad(incident.bad_state_summary())
    print()
    inc = incident.declare_incident()
    rec = inc.to_record()
    good(f"{rec['id']}  [{rec['severity']}] {rec['title']}")
    good(f"roles: {', '.join(f'{k}={v}' for k, v in rec['roles'].items())}")
    print()
    for t in rec["timeline"]:
        clock = t["at"][11:19]
        print(f"        | {clock}  {t['action']}")
        print(f"        |           evidence: {t['evidence']}")
    print()
    good(f"status={rec['status']}; postmortem actions captured: "
         f"{len(rec['postmortem_actions'])}")
    good("the incident record is the evidence for " + ", ".join(rec["evidence_for"]))


def demo_soc2() -> None:
    header("4. SOC 2 EVIDENCE MAP  (AWS-native)")
    bad(soc2.bad_state_summary())
    print()
    cov = soc2.coverage()
    good(f"{cov['controls']} controls mapped; {cov['automation_pct']}% produce "
         f"evidence continuously")
    print()
    print(f"        | {'CONTROL':8} {'OWNER':24} {'AWS SERVICE':34} EVIDENCE")
    for c in soc2.CONTROLS:
        print(f"        | {c.id:8} {c.owner:24} {c.system:34} {c.evidence}")


def demo_scanner() -> None:
    header("5. SECRET + SAST SCAN OF THE LOCAL LAB APP")
    print("  Scanning the demo's own code, never any external target.\n")
    for label, path in [("BAD ", "lab/app_bad.py"), ("GOOD", "lab/app_good.py")]:
        fs = scanner.scan_file(ROOT / path)
        s = scanner.summarize(fs)
        print(f"  {label}  | {path}: {s['total']} findings "
              f"(high={s['high']} med={s['medium']} low={s['low']})")
        for f in fs:
            print(f"        |   [{f.severity.upper():6}] L{f.line:<3} "
                  f"{f.rule}: {f.message}")
        print()
    good("the secret and the SQL-injection are caught before merge; the same "
         "scan runs in CI (.github/workflows/security.yml).")


def demo_consent() -> None:
    header("6. TCPA SMS-CONSENT GUARDRAIL")
    reg = consent.load_registry()
    sends = consent.sample_sends(reg)
    print(f"  Campaign 'Brand_X_Outreach' to {len(sends)} contacts, all at 13:00 UTC.\n")
    bad(consent.bad_state_summary())
    print()
    cleared = 0
    for s in sends:
        r = consent.evaluate_send(s, reg)
        rec = reg[s.contact_id]
        cleared += r.allowed
        tag = "ALLOW" if r.allowed else "BLOCK"
        print(f"  {tag:5} | {rec.name:12} [{rec.consent:9}] {rec.timezone:19} "
              f"{r.reasons[-1][:42]}")
    print()
    good(f"{cleared}/{len(sends)} sends cleared; the rest stopped before they went "
         "out, each with a TCPA evidence record.")


def demo_threatmodel() -> None:
    header("7. THREAT MODEL  (STRIDE, model-as-data)")
    cov = threatmodel.coverage()
    print(f"  {cov['total']} threats across STRIDE; {cov['mitigated_pct']}% fully "
          f"mitigated, the rest are the honest to-do list.\n")
    good(f"by status: {cov['by_status']}")
    good("every threat maps to a control that exists (a test enforces this).")
    print()
    bad("open gaps (partial/accepted):")
    for t in threatmodel.gaps():
        print(f"        | {t.id} [{t.stride}] {t.description[:48]} -> {t.control}")


def demo_pentest() -> None:
    header("8. PENTEST REMEDIATION TRACKER")
    today = date(2026, 6, 22)
    fs = pentest.load_findings()
    s = pentest.summary(fs, today)
    bad("a report is just a PDF until findings are owned and closed.")
    print()
    good(f"{s['total']} findings; {s['open']} open, {s['overdue']} overdue, "
         f"{s['on_time_pct']}% of open work within SLA")
    for f in pentest.worklist(fs, today)[:4]:
        tag = "OVERDUE" if pentest.is_overdue(f, today) else f"{pentest.days_left(f, today)}d left"
        print(f"        | {f.severity:8} [{tag:9}] {f.id} owner={f.owner}  {f.title[:36]}")


def demo_dast() -> None:
    header("9. DAST  (runtime checks, the dynamic half of CI)")
    for label, target in [("BAD ", dast.bad_target), ("GOOD", dast.good_target)]:
        fs = dast.probe(target)
        print(f"  {label}  | {dast.summarize(fs)}")
        for f in fs:
            print(f"        |   [{f.severity.upper():6}] {f.endpoint} {f.rule}")
    good("auth, security headers, and error leakage checked against the running app; "
         "the hardened target is clean and gates CI.")


def demo_autoresponse() -> None:
    header("10. GUARDDUTY AUTO-RESPONSE  (detection-as-code)")
    actions = autoresponse.respond(autoresponse.SAMPLE_FINDING)
    print(f"  finding: {autoresponse.SAMPLE_FINDING['type']} "
          f"(sev {autoresponse.SAMPLE_FINDING['severity']})\n")
    for a in actions:
        flag = "DESTRUCTIVE" if a.destructive else "safe"
        print(f"  GOOD  | [{flag:11}] {a.action} -> {a.target}")
    print()
    unknown = autoresponse.respond({"type": "Recon:Novel", "severity": 9.0, "resource": "x"})
    good(f"safety: an unknown finding type takes destructive action = "
         f"{autoresponse.took_destructive_action(unknown)} (alert only)")


def demo_baseline() -> None:
    header("11. IaC SECURE BASELINE  (preventive: SCP + Config)")
    bad("detective controls alone only find problems after they exist.")
    print()
    good(f"{len(baseline.SCPS)} SCP guardrails make the insecure action impossible "
         f"org-wide; {len(baseline.CONFIG_RULES)} Config rules catch drift.")
    for s in baseline.SCPS[:3]:
        print(f"        | DENY {s.name:24} prevents {s.prevents}  ({s.description[:36]})")
    print()
    nc = baseline.noncompliant(baseline.SAMPLE_ACCOUNT)
    good(f"sample account: {len(nc)} Config rules non-compliant (drift to fix):")
    for c in nc[:4]:
        print(f"        | [{c.severity.upper():6}] {c.rule}")
    print()
    good("rendered to IaC: SCP policy JSON + Terraform aws_config_config_rule, "
         "applied in the AWS Org.")


def demo_ai_appsec() -> None:
    header("12. AI RED-TEAM + CONNECTOR AUTHZ + RELEASE GATE")
    # input -> model -> output guardrail
    inj = redteam.scan_input(redteam.SAMPLE_INJECTION)
    good("prompt-injection caught on input: " + ", ".join(f.rule for f in inj))
    v = redteam.check_output(redteam.SAMPLE_BAD_OUTPUT, allowed_tools={"search", "summarize"})
    good(f"model output blocked ({len(v.reasons)}): leaks secret/PII, reveals prompt, "
         "unauthorized tool call")
    print()
    # connector authz for the internal AI app-builder
    seen = {("user:alice", "email"), ("agent:outreach", "email"), ("agent:outreach", "crm")}
    for p, c, a in [("user:alice", "email", "send"),
                    ("agent:outreach", "crm", "export"),
                    ("agent:outreach", "prod_db", "write")]:
        d = connectors.authorize(p, c, a, connectors.SAMPLE_GRANTS, seen=seen)
        tag = "ALLOW" if d.allowed else "DENY"
        print(f"        | {tag:5} {p:16} -> {c}.{a:7} high_risk={d.high_risk} anomalous={d.anomalous}")
    print()
    # release gate over the cloud findings (risk-driven, not vendor label)
    r = release_gate.evaluate(release_gate.from_triage(triage.load_findings()),
                              today=date(2026, 6, 24))
    bad("ship everything blindly? no.")
    good(f"release gate: {r.decision}, {len(r.blockers)} blockers must be fixed or "
         "accepted via a time-boxed exception.")


def main() -> None:
    print(BAR)
    print("  Agentic Security Demo: turning security tools into operating controls")
    print("  Synthetic data. Domain-neutral; AWS-native where it counts. Does not")
    print("  touch any real environment.")
    print(BAR)
    demo_governance()
    demo_triage()
    demo_incident()
    demo_soc2()
    demo_scanner()
    demo_consent()
    demo_threatmodel()
    demo_pentest()
    demo_dast()
    demo_autoresponse()
    demo_baseline()
    demo_ai_appsec()
    print(f"\n{BAR}")
    print("  One pattern across every domain: classify the risk -> assign an owner")
    print("  -> enforce a control -> produce evidence -> escalate the exception.")
    print(BAR)


if __name__ == "__main__":
    main()
