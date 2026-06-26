"""Structured security incident lifecycle (AWS-native containment).

The incident record is the operating evidence: a declared incident with a
severity, named roles, a timestamped timeline, and a postmortem is both how you
respond and how you prove the response operated for SOC 2.

Scenario: GuardDuty flags use of a leaked IAM access key. The containment steps
are AWS-native (disable the key, isolate the instance, rotate secrets, hunt for
persistence in CloudTrail). The lifecycle is domain-neutral; in a regulated
industry the same record also feeds breach-notification timelines.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


SEVERITY = {
    "Sev1": "Confirmed compromise with data-loss or exec/customer impact",
    "Sev2": "Suspected compromise, contained scope, no confirmed data loss",
    "Sev3": "Low-impact security event, routine handling",
}

ROLES = ["Incident Lead", "Comms", "Ops/Containment", "Scribe"]


@dataclass
class TimelineEntry:
    at: str
    actor: str
    action: str
    evidence: str


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    declared_at: str
    roles: dict[str, str]
    timeline: list[TimelineEntry] = field(default_factory=list)
    status: str = "open"
    postmortem_actions: list[str] = field(default_factory=list)

    def to_record(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "severity_meaning": SEVERITY.get(self.severity, ""),
            "declared_at": self.declared_at,
            "roles": self.roles,
            "status": self.status,
            "timeline": [vars(t) for t in self.timeline],
            "postmortem_actions": self.postmortem_actions,
            "evidence_for": ["SOC2-CC7.3", "SOC2-CC7.4", "IR-Playbook"],
        }


def declare_incident(*, now: datetime | None = None) -> Incident:
    """The 'good' state: a structured incident instead of a Slack DM."""
    now = now or datetime.now(timezone.utc)
    inc = Incident(
        id=f"INC-{uuid.uuid4().hex[:6]}",
        title="GuardDuty flags use of a leaked IAM access key",
        severity="Sev2",
        declared_at=now.isoformat(),
        roles={
            "Incident Lead": "you (security)",
            "Comms": "eng manager",
            "Ops/Containment": "platform on-call",
            "Scribe": "security analyst",
        },
    )

    # Every step records the artifact it produced, so when the incident closes the
    # timeline is the evidence and no one has to reconstruct it later for the audit.
    def step(mins: int, actor: str, action: str, evidence: str) -> None:
        inc.timeline.append(TimelineEntry(
            (now + timedelta(minutes=mins)).isoformat(), actor, action, evidence))

    step(0, "security", "Declared Sev2 from the GuardDuty finding",
         "incident record + GuardDuty finding id")
    step(2, "ops", "Disabled the exposed IAM access key; attached a deny-all policy",
         "IAM change + CloudTrail event")
    step(4, "ops", "Isolated the affected EC2 with a quarantine security group",
         "security-group change + CloudTrail event")
    step(6, "ops", "Rotated the key and reachable Secrets Manager secrets",
         "Secrets Manager rotation record")
    step(9, "security", "Hunted persistence in CloudTrail (new IAM users/keys, unusual AssumeRole)",
         "CloudTrail + GuardDuty query results")
    step(12, "comms", "Notified stakeholders and the data owner",
         "stakeholder notice")
    step(20, "security", "Confirmed blast radius scoped to one principal",
         "CloudTrail + Security Hub query results")
    inc.status = "contained"
    inc.postmortem_actions = [
        "Auto-disable keys on GuardDuty UnauthorizedAccess:IAMUser via EventBridge",
        "Replace static keys with short-lived creds from IAM Identity Center",
        "Require phishing-resistant MFA for console and CLI",
    ]
    return inc


def bad_state_summary() -> str:
    """What this looks like without a control: an unmanaged DM thread."""
    return ("Someone pastes the GuardDuty alert into a chat; no severity, no roles, "
            "no timeline. Containment depends on who happens to be online. No "
            "evidence is produced, so the response cannot be audited or improved.")
