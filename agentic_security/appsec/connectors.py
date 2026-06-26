"""Connector authorization + audit for an internal AI app-builder.

The scenario: a low-code AI tool where people wire agents to connectors (email,
calendar, CRM, prod database, object storage). The risk is over-broad access and
no attribution. This enforces least privilege per action and emits an audit
record, so you can answer "who used which connector, for what, and was it allowed."

Stdlib only. Synthetic grants.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

# Connectors and the scopes each supports.
CONNECTORS: dict[str, set[str]] = {
    "email": {"read", "send"},
    "calendar": {"read", "write"},
    "crm": {"read", "write", "export"},
    "prod_db": {"read", "write"},
    "object_store": {"read", "write"},
}

# Actions that are sensitive even when granted (flag for review).
HIGH_RISK = {("crm", "export"), ("prod_db", "write"), ("object_store", "write")}


@dataclass
class Grant:
    principal: str             # "user:alice" or "agent:outreach"
    connector: str
    scopes: set[str]


@dataclass
class AuthzDecision:
    allowed: bool
    reason: str
    high_risk: bool
    anomalous: bool
    audit: dict


def _principal_token(principal: str) -> str:
    return "tok_" + hashlib.sha256(principal.encode()).hexdigest()[:8]


def _grant_for(principal: str, connector: str, grants: list[Grant]) -> Optional[Grant]:
    for g in grants:
        if g.principal == principal and g.connector == connector:
            return g
    return None


def authorize(principal: str, connector: str, action: str, grants: list[Grant],
              *, seen: Optional[set[tuple[str, str]]] = None) -> AuthzDecision:
    """Allow or deny one action on one connector, least-privilege by default.
    `seen` is the set of (principal, connector) pairs observed before; a new pair
    is flagged anomalous (first-time access) for review."""
    anomalous = seen is not None and (principal, connector) not in seen
    valid_scopes = CONNECTORS.get(connector)

    if valid_scopes is None:
        allowed, reason = False, f"unknown connector '{connector}'"
    elif action not in valid_scopes:
        allowed, reason = False, f"'{action}' is not a valid scope on '{connector}'"
    else:
        grant = _grant_for(principal, connector, grants)
        if grant is None:
            allowed, reason = False, f"{principal} has no grant for '{connector}' (least privilege)"
        elif action not in grant.scopes:
            allowed, reason = False, f"{principal} lacks '{action}' on '{connector}'"
        else:
            allowed, reason = True, "granted"

    high_risk = (connector, action) in HIGH_RISK
    audit = {
        "principal_token": _principal_token(principal),   # never the raw principal
        "connector": connector,
        "action": action,
        "decision": "ALLOW" if allowed else "DENY",
        "reason": reason,
        "high_risk": high_risk,
        "anomalous": anomalous,
        "control": "connector-authz",
        "evidence_for": ["SOC2-CC6.1", "SOC2-CC6.3"],
    }
    return AuthzDecision(allowed, reason, high_risk, anomalous, audit)


# Sample least-privilege grants for the demo.
SAMPLE_GRANTS = [
    Grant("user:alice", "email", {"read", "send"}),
    Grant("user:alice", "calendar", {"read", "write"}),
    Grant("agent:outreach", "email", {"send"}),
    Grant("agent:outreach", "crm", {"read"}),
]


if __name__ == "__main__":
    seen = {("user:alice", "email"), ("agent:outreach", "email"), ("agent:outreach", "crm")}
    cases = [
        ("user:alice", "email", "send"),        # granted
        ("agent:outreach", "crm", "export"),    # denied: lacks export (least privilege)
        ("agent:outreach", "prod_db", "write"), # denied: no grant + high risk + anomalous
    ]
    for p, c, a in cases:
        d = authorize(p, c, a, SAMPLE_GRANTS, seen=seen)
        print(f"{d.audit['decision']:5} {p} -> {c}.{a}  high_risk={d.high_risk} anomalous={d.anomalous}  ({d.reason})")
