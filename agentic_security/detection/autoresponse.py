"""GuardDuty finding -> automated response plan (detection-as-code).

What an EventBridge rule + Lambda would do when GuardDuty raises a finding. It
returns the plan instead of calling AWS, so it is deterministic and testable.

Safety rule: destructive actions (disable a key, isolate an instance) only fire on
a *known* finding type at or above a severity threshold. An unknown type, or a
low-severity one, gets alert + ticket only, never an automated destructive action.
That keeps the auto-responder from doing damage on a noisy or novel signal.
"""

from __future__ import annotations

from dataclasses import dataclass

# GuardDuty severity is 0.1-8.9; >= 7.0 is "High".
DESTRUCTIVE_THRESHOLD = 7.0

# Actions that change state (vs. alert/ticket, which are always safe).
DESTRUCTIVE = {"disable_iam_key", "isolate_instance", "revoke_public_access", "quarantine_role"}


@dataclass
class ResponseAction:
    action: str
    target: str
    destructive: bool
    reason: str


# Known finding-type prefix -> the destructive actions it warrants.
_RULES: list[tuple[str, list[str]]] = [
    ("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
     ["disable_iam_key", "isolate_instance"]),
    ("UnauthorizedAccess:IAMUser", ["disable_iam_key"]),
    ("Backdoor:EC2", ["isolate_instance"]),
    ("Trojan:EC2", ["isolate_instance"]),
    ("Exfiltration:S3", ["revoke_public_access"]),
    ("Policy:S3/BucketPublicAccessGranted", ["revoke_public_access"]),
    ("PrivilegeEscalation:IAMUser", ["quarantine_role"]),
]


def _match(finding_type: str) -> list[str]:
    for prefix, actions in _RULES:
        if finding_type.startswith(prefix):
            return actions
    return []


def respond(finding: dict) -> list[ResponseAction]:
    """finding = {"type": <guardduty type>, "severity": float, "resource": str}."""
    ftype = finding.get("type", "")
    severity = float(finding.get("severity", 0))
    target = finding.get("resource", "unknown")
    actions: list[ResponseAction] = []

    destructive = _match(ftype)
    if destructive and severity >= DESTRUCTIVE_THRESHOLD:
        for a in destructive:
            actions.append(ResponseAction(a, target, True,
                                          f"{ftype} at severity {severity}"))
    elif destructive:
        # Known type but below threshold: do not auto-remediate, just escalate.
        actions.append(ResponseAction("alert", target, False,
                                      f"{ftype} below auto-remediation threshold"))
    else:
        # Unknown type: never take a destructive action on a signal we don't model.
        actions.append(ResponseAction("alert", target, False,
                                      f"unrecognized finding type: {ftype or 'n/a'}"))

    # Every response, destructive or not, opens an incident and notifies.
    actions.append(ResponseAction("open_incident", target, False, "track the response"))
    actions.append(ResponseAction("notify", "security-oncall", False, "page on-call"))
    return actions


def took_destructive_action(actions: list[ResponseAction]) -> bool:
    return any(a.destructive for a in actions)


SAMPLE_FINDING = {
    "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "severity": 8.0,
    "resource": "AKIAEXAMPLE / i-0abc123",
}


if __name__ == "__main__":
    for a in respond(SAMPLE_FINDING):
        flag = "DESTRUCTIVE" if a.destructive else "safe"
        print(f"  [{flag:11}] {a.action} -> {a.target}: {a.reason}")
