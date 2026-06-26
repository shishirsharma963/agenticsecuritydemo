"""SOC 2 evidence map (AWS-native).

SOC 2 is not a document-gathering exercise. Each control maps to an owner, an AWS
service that already emits its evidence, and that evidence. The goal is continuous
evidence, where the control's normal operation is the proof. The control set is
domain-neutral; in a regulated industry the same map underpins HIPAA/PCI/GDPR
audits too.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Control:
    id: str
    name: str
    owner: str
    system: str
    evidence: str
    cadence: str
    automated: bool


# Each row ties a control to the system that *already* emits its evidence, so the
# proof is a by-product of normal operation rather than a screenshot scramble at
# audit time. `automated=True` means the evidence is continuous, not point-in-time.
CONTROLS: list[Control] = [
    Control("CC6.1", "Encryption at rest", "Engineering / Security", "KMS + S3/EBS/RDS",
            "AWS Config rule: encryption-enabled status", "continuous", True),
    Control("CC6.6", "Network boundary", "Engineering / Security", "Security Groups + VPC",
            "Config + Security Hub conformance pack", "continuous", True),
    Control("CC7.1", "Vuln remediation", "Engineering / Security", "Security Hub + Inspector + ticketing",
            "Closed ticket linked to finding status", "continuous", True),
    Control("CC7.2", "Threat detection", "Security", "GuardDuty + CloudTrail",
            "GuardDuty findings + response records", "continuous", True),
    Control("CC7.3", "Incident response", "Security / Eng", "runbooks + ticketing",
            "Incident timeline + postmortem", "per-incident", True),
    Control("CC6.3", "AI acceptable use", "Security / AI Eng", "AI admin logs + ticketing",
            "Policy + AI-usage governance audit records", "monthly review", True),
    Control("CC6.2", "Access reviews", "Security / Eng", "IAM Identity Center + Access Analyzer",
            "Quarterly access-review attestation", "quarterly", False),
    Control("CC8.1", "Change management", "Engineering", "source control + CI",
            "PR review + CI run (SAST/DAST) on every merge", "per-change", True),
]


def coverage() -> dict:
    total = len(CONTROLS)
    automated = sum(1 for c in CONTROLS if c.automated)
    return {
        "controls": total,
        "automated": automated,
        "manual": total - automated,
        "automation_pct": round(automated / total * 100),
    }


def bad_state_summary() -> str:
    return ("The data exists (Security Hub, GuardDuty, Config, CloudTrail) but lives "
            "in separate consoles. At audit time someone screenshots each one into a "
            "spreadsheet. Nothing proves the control operated *between* audits.")
