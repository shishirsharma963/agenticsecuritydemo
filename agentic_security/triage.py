"""AWS cloud finding triage.

A few hundred findings are not a few hundred equal problems. Aggregated AWS
Security Hub findings (from GuardDuty, Inspector, Config, Macie, IAM Access
Analyzer) come with a severity label that scatters the few that actually form an
attack path (public + sensitive data + exploitable + privileged IAM) across the
list. This module re-ranks by toxic combination, the way attack-path analysis
does. Domain-neutral: the same scoring applies wherever findings have these
factors; in a regulated industry, "sensitive data" is the PHI/PCI/PII tier.

    Risk score weights (additive):
        internet_facing      30
        sensitive_data       25
        exploitable_high     20
        privileged_iam       20
        production           15
        missing_logging      10
        owner_unknown        10
        manually_provisioned 10

Findings are synthetic (seeded), with a few attack paths guaranteed so the demo
always has criticals. Additive weighting is a simplification; mature attack-path
analysis uses graph reachability plus signals like EPSS and data-sensitivity
tiers.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Weighting encodes one idea: risk tracks reachability, value, and exploitability,
# so the factors that make a finding reachable and valuable carry the most weight.
# A finding becomes urgent only when several stack on the same resource.
WEIGHTS = {
    "internet_facing": 30,
    "sensitive_data": 25,
    "exploitable_high": 20,
    "privileged_iam": 20,
    "production": 15,
    "missing_logging": 10,
    "owner_unknown": 10,
    "manually_provisioned": 10,
}

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "cloud_findings.json"


@dataclass
class Finding:
    id: str
    title: str
    resource: str
    vendor_severity: str            # what the tool labels it: critical/high/medium/low
    internet_facing: bool = False
    sensitive_data: bool = False
    exploitable_high: bool = False
    privileged_iam: bool = False
    production: bool = False
    missing_logging: bool = False
    owner_unknown: bool = False
    manually_provisioned: bool = False
    owner: str = "unassigned"

    def risk_score(self) -> int:
        return sum(w for k, w in WEIGHTS.items() if getattr(self, k))

    def factors(self) -> list[str]:
        return [k for k in WEIGHTS if getattr(self, k)]

    def is_attack_path(self) -> bool:
        # The classic toxic combination: reachable + valuable + breakable.
        return self.internet_facing and self.sensitive_data and self.exploitable_high

    def risk_band(self) -> str:
        s = self.risk_score()
        if s >= 85:
            return "Critical"
        if s >= 55:
            return "High"
        if s >= 30:
            return "Medium"
        return "Low"


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_findings(path: Path = DATA_FILE) -> list[Finding]:
    raw = json.loads(Path(path).read_text())
    return [Finding(**r) for r in raw]


def vendor_view(findings: list[Finding]) -> list[Finding]:
    """The 'bad' view: sort by the vendor's severity label only.

    A vendor severity describes the issue in isolation, not its blast radius in
    your environment, so sorting by it buries the findings that form a real attack
    path among hundreds that only look critical."""
    return sorted(findings, key=lambda f: _SEV_RANK.get(f.vendor_severity, 9))


def risk_view(findings: list[Finding]) -> list[Finding]:
    """The 'good' view: attack paths first, then by computed risk score."""
    return sorted(findings, key=lambda f: (not f.is_attack_path(), -f.risk_score()))


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings (same title + resource). Real scanners emit the
    same issue many times; dedupe before you count, so the number you report is the
    real one, not the raw alert count (the '300 findings, some duplicates' problem)."""
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.title, f.resource)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# --------------------------------------------------------------------------- #
# Synthetic data generator (seeded, reproducible)                              #
# --------------------------------------------------------------------------- #
_CATEGORIES = [
    ("S3 bucket public (Block Public Access off)", "arn:aws:s3:::prod-bucket-{n}"),
    ("Security group open to 0.0.0.0/0 on 22/3389", "sg-{n}"),
    ("RDS instance publicly accessible", "rds:prod-db-{n}"),
    ("IAM role with wildcard (*) permissions", "iam-role/svc-{n}"),
    ("IAM access key unused >90 days", "iam-user/contractor-{n}"),
    ("EBS volume unencrypted at rest", "vol-{n}"),
    ("CloudTrail not enabled in a region", "account/region-{n}"),
    ("ECR image with critical CVE (Inspector)", "ecr/image-{n}"),
    ("Lambda with over-broad execution role", "lambda:fn-{n}"),
    ("EC2 with known-exploited CVE (Inspector)", "i-{n}"),
    ("Secret in plaintext env var (use Secrets Manager)", "ecs:task-{n}"),
    ("S3 data events not logged in CloudTrail", "arn:aws:s3:::data-{n}"),
    ("Resource created outside IaC (Terraform/CDK)", "manual/res-{n}"),
    ("Orphaned dev/test EC2 instance", "i-dev-{n}"),
    ("KMS key policy too permissive", "kms/key-{n}"),
]


def generate(seed: int = 42, n: int = 240) -> list[Finding]:
    rnd = random.Random(seed)
    findings: list[Finding] = []
    for i in range(n):
        title, res = rnd.choice(_CATEGORIES)
        # Most findings are mundane; a minority stack into attack paths.
        prod = rnd.random() < 0.45
        sensitive = rnd.random() < 0.20
        internet = rnd.random() < 0.18
        exploit = rnd.random() < 0.15
        priv = rnd.random() < 0.18
        f = Finding(
            id=f"FIND-{1000 + i}",
            title=title,
            resource=res.format(n=rnd.randint(100, 999)),
            # Vendor severity is deliberately noisy vs. real blast radius.
            vendor_severity=rnd.choice(["critical", "high", "high", "medium", "medium", "low"]),
            internet_facing=internet,
            sensitive_data=sensitive,
            exploitable_high=exploit,
            privileged_iam=priv,
            production=prod,
            missing_logging=rnd.random() < 0.30,
            owner_unknown=rnd.random() < 0.40,
            manually_provisioned=rnd.random() < 0.25,
            owner="unassigned" if rnd.random() < 0.40 else rnd.choice(
                ["team-platform", "team-data", "team-mobile", "team-infra"]),
        )
        findings.append(f)

    # Guarantee a few unambiguous attack paths so the demo always has criticals.
    for j in range(4):
        findings[j].internet_facing = True
        findings[j].sensitive_data = True
        findings[j].exploitable_high = True
        findings[j].privileged_iam = True
        findings[j].production = True
        findings[j].vendor_severity = rnd.choice(["high", "medium"])  # under-rated by vendor!
        findings[j].title = "Internet-facing EC2 + sensitive S3 data + exploitable CVE + broad IAM"
        findings[j].resource = f"i-attackpath-{j}"
        findings[j].owner = "unassigned"
        findings[j].owner_unknown = True
    return findings


def write_data(path: Path = DATA_FILE, seed: int = 42, n: int = 240) -> int:
    findings = generate(seed=seed, n=n)
    Path(path).write_text(json.dumps([asdict(f) for f in findings], indent=2))
    return len(findings)


if __name__ == "__main__":
    count = write_data()
    print(f"wrote {count} synthetic findings to {DATA_FILE}")
