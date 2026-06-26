"""Secret + SAST-lite static scanner.

Scans source files and reports findings. Used two ways:
  * the demo runs it over lab/app_bad.py and lab/app_good.py to show
    insecure-vs-hardened;
  * CI runs it (via the test suite) to assert the control works, app_bad has the
    expected findings, app_good has none. That keeps CI green while proving the
    scanner actually catches things.

Pure stdlib. Findings are deterministic.

This is a lightweight scanner: line regex plus a decorator-block check for
unauthenticated routes. It is easily evaded and is not a replacement for a real
SAST engine or secret scanner; what it demonstrates is the wiring (scan, gate in
CI, leave evidence), not detection coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanFinding:
    rule: str
    severity: str                   # high | medium | low
    line: int
    snippet: str
    message: str


# (rule_id, severity, regex, message)
_RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("hardcoded-aws-key", "high", re.compile(r"AKIA[0-9A-Z]{16}"),
     "Hardcoded AWS access key id committed to source"),
    ("hardcoded-secret-assign", "high",
     re.compile(r"(?i)(secret|api_key|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"),
     "Secret assigned as a string literal in source"),
    ("sql-string-concat", "high",
     re.compile(r"(?i)SELECT\s+.+\+\s*\w+|SELECT\s+.+%\s*\(|\"\s*\+\s*\w+\s*\+\s*\""),
     "SQL query built by string concatenation (injection risk)"),
    ("flask-debug-true", "medium", re.compile(r"debug\s*=\s*True"),
     "Flask debug mode enabled (RCE via debugger)"),
    ("bind-all-interfaces", "low", re.compile(r"host\s*=\s*['\"]0\.0\.0\.0['\"]"),
     "Service bound to all interfaces"),
]

# A route is 'unauthenticated' if a Flask route decorator is not immediately
# preceded/followed by an auth decorator before the function def.
_ROUTE_RE = re.compile(r"@app\.route\(")
_AUTH_RE = re.compile(r"@require_auth|@login_required|@requires_auth")


def scan_text(text: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    lines = text.splitlines()

    for i, line in enumerate(lines, start=1):
        for rule, sev, pat, msg in _RULES:
            if pat.search(line):
                findings.append(ScanFinding(rule, sev, i, line.strip()[:80], msg))

    # A common authz bug is simply an endpoint missing its auth decorator. Read the
    # decorator block above each route and flag any that reach `def` without one.
    for i, line in enumerate(lines):
        if _ROUTE_RE.search(line):
            # Collect decorator lines until we hit the function definition.
            j = i
            has_auth = False
            while j < len(lines) and not lines[j].lstrip().startswith("def "):
                if _AUTH_RE.search(lines[j]):
                    has_auth = True
                j += 1
            if not has_auth:
                findings.append(ScanFinding(
                    "unauthenticated-endpoint", "high", i + 1,
                    line.strip()[:80], "Route exposed without an authentication decorator"))
    return findings


def scan_file(path: str | Path) -> list[ScanFinding]:
    return scan_text(Path(path).read_text())


def summarize(findings: list[ScanFinding]) -> dict:
    out = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    out["total"] = len(findings)
    return out


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "lab/app_bad.py"
    fs = scan_file(target)
    print(f"== {target}: {summarize(fs)} ==")
    for f in fs:
        print(f"  [{f.severity.upper():6}] L{f.line:<3} {f.rule}: {f.message}")
    # Non-zero exit if any high finding (CI gate behaviour for arbitrary targets).
    sys.exit(1 if any(f.severity == "high" for f in fs) else 0)
