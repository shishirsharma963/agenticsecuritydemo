"""Structured STRIDE threat model for the AI/agent platform.

This is the threat model as data, not just prose (see THREAT_MODEL.md for the
narrative + data-flow). Every threat names the control that mitigates it, and a
test asserts that control actually exists in the package. That keeps the model
honest: a threat with no real control shows up as a gap, not a paragraph.

STRIDE: Spoofing, Tampering, Repudiation, Information disclosure, Denial of
service, Elevation of privilege. LLM refs are OWASP Top 10 for LLM Apps; ATLAS
refs are MITRE ATLAS tactics.
"""

from __future__ import annotations

from dataclasses import dataclass

# Controls implemented in this repo. A threat may only claim one of these.
VALID_CONTROLS = {
    "governance", "identity", "consent", "triage",
    "incident", "soc2", "scanner", "dast", "autoresponse", "baseline",
    "redteam", "connectors", "release_gate",
}

STRIDE = {"S", "T", "R", "I", "D", "E"}
STATUS = {"mitigated", "partial", "accepted"}


@dataclass
class Threat:
    id: str
    stride: str          # one of STRIDE
    component: str        # where in the data flow
    description: str
    mitigation: str
    control: str          # must be in VALID_CONTROLS
    status: str           # one of STATUS
    ref: str = ""         # OWASP-LLM / ATLAS reference


THREATS: list[Threat] = [
    Threat("T01", "S", "agent chain",
           "An agent forges or replays another agent's identity in the actor chain",
           "Per-hop short-lived signed tokens; the gateway verifies the whole chain",
           "identity", "mitigated", "ATLAS: Valid Accounts"),
    Threat("T02", "T", "AI guardrail",
           "Prompt injection steers an agent or leaks data through the model output",
           "Input injection detection + output validation (leaks, revealed prompt, unauthorized tool calls)",
           "redteam", "mitigated", "LLM01 Prompt Injection"),
    Threat("T03", "I", "AI guardrail",
           "Secrets or PII are sent to a model and leak / get trained on",
           "DLP classification, secret block, tokenization, DPA-only routing",
           "governance", "mitigated", "LLM02 Sensitive Information Disclosure"),
    Threat("T04", "I", "AI tool egress",
           "Regulated data exfiltrated to an unapproved consumer AI tool",
           "Approved-tool registry; regulated data only to DPA-covered endpoints",
           "governance", "mitigated", "ATLAS: Exfiltration"),
    Threat("T05", "R", "audit",
           "Cannot prove which human, through which agents, did an action",
           "Signed actor chain written into one audit record per request",
           "identity", "mitigated", ""),
    Threat("T06", "E", "AWS IAM",
           "Over-broad IAM role or privilege-escalation path",
           "Least privilege + Access Analyzer; attack-path triage surfaces it",
           "triage", "partial", "ATLAS: Privilege Escalation"),
    Threat("T07", "S", "AWS IAM",
           "A leaked IAM access key is used from an unexpected location",
           "GuardDuty detection drives an automated key-disable + isolation",
           "autoresponse", "mitigated", "ATLAS: Valid Accounts"),
    Threat("T08", "T", "agent tools",
           "Excessive agent agency: an agent calls tools beyond its intent",
           "Per-hop intent + audience-scoped tokens checked at the gateway",
           "identity", "partial", "LLM08 Excessive Agency"),
    Threat("T09", "I", "AWS data stores",
           "Public S3 bucket or exposed datastore leaks sensitive data",
           "Attack-path triage prioritizes internet-facing + sensitive findings",
           "triage", "partial", "ATLAS: Exfiltration"),
    Threat("T10", "D", "AI spend",
           "Unbounded token spend (runaway agents) drains budget / availability",
           "Per-request spend attribution to a cost center; budget alerts in V2",
           "governance", "partial", "LLM10 Unbounded Consumption"),
    Threat("T11", "R", "compliance",
           "No continuous evidence that controls operated between audits",
           "Each control mapped to the AWS service that emits its evidence",
           "soc2", "mitigated", ""),
    Threat("T12", "T", "SDLC",
           "Insecure code ships (hardcoded secret, SQL injection, open endpoint)",
           "SAST + secret scan + DAST gated in CI before merge",
           "scanner", "mitigated", "ATLAS: Supply Chain"),
    Threat("T13", "I", "outbound messaging",
           "Message sent to a contact without consent (TCPA exposure)",
           "Consent + opt-out + quiet-hours check before every send",
           "consent", "mitigated", ""),
    Threat("T14", "T", "app surface",
           "Running app exposes an unauthenticated endpoint or leaks errors",
           "DAST checks for auth, security headers, and error/debug leakage",
           "dast", "mitigated", ""),
    Threat("T15", "T", "AWS account",
           "Config drift loosens the secure baseline (public S3, logging off, IMDSv1)",
           "SCP guardrails prevent the change; Config rules catch drift",
           "baseline", "mitigated", "ATLAS: Defense Evasion"),
    Threat("T16", "E", "AI app-builder",
           "An agent or user over-reaches connectors (email, CRM, prod) it was not granted",
           "Per-action connector authorization, least privilege, anomalous-access flags, audit",
           "connectors", "mitigated", "LLM08 Excessive Agency"),
    Threat("T17", "T", "release",
           "A blocking finding ships without a documented risk decision",
           "Release gate: critical or attack-path blocks unless a time-boxed exception is approved",
           "release_gate", "mitigated", ""),
]


def coverage() -> dict:
    by_status = {s: sum(1 for t in THREATS if t.status == s) for s in STATUS}
    by_stride = {s: sum(1 for t in THREATS if t.stride == s) for s in STRIDE}
    return {
        "total": len(THREATS),
        "by_status": by_status,
        "by_stride": by_stride,
        "mitigated_pct": round(by_status["mitigated"] / len(THREATS) * 100),
    }


def gaps() -> list[Threat]:
    """Threats that are not fully mitigated, i.e. the honest to-do list."""
    return [t for t in THREATS if t.status != "mitigated"]
