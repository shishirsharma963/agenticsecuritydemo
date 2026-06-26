"""DAST: runtime checks against a running app (the dynamic half of the JD's
"DAST and SAST in CI/CD").

SAST (scanner.py) reads source; DAST exercises the running app and checks how it
*behaves*: are protected routes actually authenticated, are security headers set,
does it leak stack traces. To stay deterministic and zero-dependency, a target is
just a callable `request(path, authed) -> Response`. In CI you would point the
same probe at the hardened app's test client or a deployed URL; here we hand it a
synthetic bad target and good target so the contrast runs with no server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# Routes that must require authentication.
PROTECTED = ["/admin", "/api/customer-profile", "/api/campaigns"]
# Headers a hardened app should set on responses.
REQUIRED_HEADERS = ["X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]


@dataclass
class Response:
    status: int
    headers: dict
    body: str


@dataclass
class DastFinding:
    rule: str
    severity: str          # high | medium | low
    endpoint: str
    message: str


# A target answers requests. `authed=False` means no/invalid credentials.
Target = Callable[[str, bool], Response]


def probe(target: Target) -> list[DastFinding]:
    findings: list[DastFinding] = []

    for path in PROTECTED:
        # Unauthenticated access to a protected route must be refused.
        r = target(path, False)
        if r.status not in (401, 403):
            findings.append(DastFinding(
                "missing-authentication", "high", path,
                f"protected route returned {r.status} without credentials"))

        # Authenticated responses should carry baseline security headers and must
        # not leak stack traces / debug output.
        ra = target(path, True)
        missing = [h for h in REQUIRED_HEADERS if h not in ra.headers]
        if missing:
            findings.append(DastFinding(
                "missing-security-headers", "medium", path,
                f"missing headers: {', '.join(missing)}"))
        if "Traceback" in ra.body or "Werkzeug" in ra.body:
            findings.append(DastFinding(
                "error-leakage", "high", path,
                "response body leaks a stack trace / debug page"))
    return findings


def summarize(findings: list[DastFinding]) -> dict:
    out = {"high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


# --------------------------------------------------------------------------- #
# Synthetic targets: the deployed bad app vs. the hardened good app.           #
# --------------------------------------------------------------------------- #
def bad_target(path: str, authed: bool) -> Response:
    # Serves protected routes with no auth, no security headers, and leaks errors.
    if path == "/api/customer-profile":
        return Response(200, {}, "Traceback (most recent call last): ...")
    return Response(200, {}, '{"data": "ok"}')


def good_target(path: str, authed: bool) -> Response:
    headers = {h: "set" for h in REQUIRED_HEADERS}
    if not authed:
        return Response(401, headers, "unauthorized")
    return Response(200, headers, '{"data": "ok"}')


if __name__ == "__main__":
    import sys
    bad = probe(bad_target)
    good = probe(good_target)
    print(f"bad  target: {summarize(bad)}")
    for f in bad:
        print(f"  [{f.severity.upper():6}] {f.endpoint} {f.rule}: {f.message}")
    print(f"good target: {summarize(good)}")
    # CI gate: the hardened target must be clean.
    sys.exit(1 if good else 0)
