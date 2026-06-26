"""IaC secure baseline: SCP guardrails + AWS Config rules.

Two layers of cloud control, expressed as data and rendered to real IaC:

  * Preventive: Service Control Policies (SCPs) that make the insecure action
    impossible org-wide (can't stop CloudTrail, can't disable GuardDuty, can't
    launch without IMDSv2, can't operate outside approved regions).
  * Detective: AWS Config rules that catch drift continuously, with a small
    evaluator that checks a mock account state so the loop is testable.

`render_scp` emits a valid SCP policy document; `render_terraform_config_rule`
emits a Terraform `aws_config_config_rule` block. Each SCP names the threat it
prevents (a test asserts those threat ids exist). Stdlib only; AWS-native.
"""

from __future__ import annotations

from dataclasses import dataclass

APPROVED_REGIONS = ["us-east-1", "us-west-2"]


@dataclass
class Scp:
    id: str
    name: str
    description: str
    deny_actions: list[str]
    condition: dict
    prevents: str          # threat id from threatmodel


@dataclass
class ConfigRule:
    name: str              # AWS managed-rule source identifier
    description: str
    severity: str          # high | medium | low
    state_key: str         # the account_state flag this rule inspects
    remediation: str


@dataclass
class ComplianceResult:
    rule: str
    status: str            # COMPLIANT | NON_COMPLIANT
    severity: str
    remediation: str


# --------------------------------------------------------------------------- #
# Preventive: Service Control Policies                                          #
# --------------------------------------------------------------------------- #
SCPS: list[Scp] = [
    Scp("scp-001", "DenyStopCloudTrail",
        "Audit logging cannot be turned off in any account",
        ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"], {}, "T15"),
    Scp("scp-002", "DenyDisableGuardDuty",
        "Threat detection cannot be removed",
        ["guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount"], {}, "T07"),
    Scp("scp-003", "DenyWeakenPublicAccessBlock",
        "S3 account-level Block Public Access cannot be loosened",
        ["s3:PutAccountPublicAccessBlock"], {}, "T09"),
    Scp("scp-004", "RequireIMDSv2",
        "EC2 must launch with IMDSv2 required (blocks SSRF credential theft)",
        ["ec2:RunInstances"],
        {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}, "T06"),
    Scp("scp-005", "RegionLock",
        "Only approved regions may be used",
        ["*"], {"StringNotEquals": {"aws:RequestedRegion": APPROVED_REGIONS}}, "T06"),
    Scp("scp-006", "DenyRootDailyUse",
        "The account root user may not perform actions",
        ["*"], {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}}, "T06"),
]


def render_scp(scp: Scp) -> dict:
    """Render an SCP to a valid IAM policy document (the artifact you'd commit)."""
    statement = {
        "Sid": scp.id.replace("-", ""),
        "Effect": "Deny",
        "Action": scp.deny_actions,
        "Resource": "*",
    }
    if scp.condition:
        statement["Condition"] = scp.condition
    return {"Version": "2012-10-17", "Statement": [statement]}


# --------------------------------------------------------------------------- #
# Detective: AWS Config rules                                                   #
# --------------------------------------------------------------------------- #
CONFIG_RULES: list[ConfigRule] = [
    ConfigRule("S3_BUCKET_PUBLIC_READ_PROHIBITED", "No public-readable S3 buckets",
               "high", "s3_public_read", "Enable Block Public Access on the bucket"),
    ConfigRule("S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED", "S3 default encryption on",
               "medium", "s3_unencrypted", "Enable default SSE-KMS"),
    ConfigRule("ENCRYPTED_VOLUMES", "EBS volumes encrypted at rest",
               "medium", "ebs_unencrypted", "Turn on EBS default encryption"),
    ConfigRule("RDS_INSTANCE_PUBLIC_ACCESS_CHECK", "RDS instances are not public",
               "high", "rds_public", "Set PubliclyAccessible = false"),
    ConfigRule("CLOUD_TRAIL_ENABLED", "CloudTrail is enabled",
               "high", "cloudtrail_disabled", "Enable an organization trail"),
    ConfigRule("IAM_USER_MFA_ENABLED", "IAM users have MFA",
               "high", "iam_no_mfa", "Enforce MFA for all users"),
    ConfigRule("IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS", "No *:* admin policies",
               "high", "iam_admin_star", "Scope policies to least privilege"),
    ConfigRule("INCOMING_SSH_DISABLED", "No security group opens 22 to 0.0.0.0/0",
               "medium", "ssh_open", "Restrict the security group"),
    ConfigRule("GUARDDUTY_ENABLED_CENTRALIZED", "GuardDuty enabled org-wide",
               "high", "guardduty_off", "Enable GuardDuty in the delegated admin"),
]


def render_terraform_config_rule(rule: ConfigRule) -> str:
    """Render a Config rule to a Terraform resource block (the artifact you'd commit)."""
    name = rule.name.lower()
    return (
        f'resource "aws_config_config_rule" "{name}" {{\n'
        f'  name = "{name}"\n'
        f'  source {{\n'
        f'    owner             = "AWS"\n'
        f'    source_identifier = "{rule.name}"\n'
        f'  }}\n'
        f'}}'
    )


def evaluate(account_state: dict) -> list[ComplianceResult]:
    """Check a mock account state against the Config rules. A state flag set to
    True means the bad condition is present (rule is NON_COMPLIANT)."""
    out: list[ComplianceResult] = []
    for r in CONFIG_RULES:
        bad = bool(account_state.get(r.state_key, False))
        out.append(ComplianceResult(
            r.name, "NON_COMPLIANT" if bad else "COMPLIANT", r.severity, r.remediation))
    return out


def noncompliant(account_state: dict) -> list[ComplianceResult]:
    return [c for c in evaluate(account_state) if c.status == "NON_COMPLIANT"]


# A mock account with several drifted settings, for the demo and tests.
SAMPLE_ACCOUNT = {
    "s3_public_read": True,
    "ebs_unencrypted": True,
    "iam_admin_star": True,
    "ssh_open": True,
    "iam_no_mfa": True,
    "rds_public": False,
    "s3_unencrypted": False,
    "cloudtrail_disabled": False,
    "guardduty_off": False,
}


if __name__ == "__main__":
    import json
    print(f"{len(SCPS)} SCP guardrails, {len(CONFIG_RULES)} Config rules\n")
    print("example SCP (DenyStopCloudTrail):")
    print(json.dumps(render_scp(SCPS[0]), indent=2))
    print("\nnon-compliant in the sample account:")
    for c in noncompliant(SAMPLE_ACCOUNT):
        print(f"  [{c.severity.upper():6}] {c.rule}: {c.remediation}")
