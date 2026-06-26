"""Release-readiness gate: turn findings into a ship / block decision.

Answers the "what's a release blocker vs. acceptable risk" question. The bar:
anything that is critical-risk or forms an attack path blocks the release, unless
there is a documented, time-boxed risk acceptance (an exception with an approver
and an expiry). Everything else ships. This is how you keep a scrappy team moving
without shipping the things that actually hurt.

Blocking is decided on real risk, not vendor severity, so it composes with the
triage module (an attack path blocks even if the scanner labeled it 'medium').
Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Optional

SHIP = "SHIP"
BLOCK = "BLOCK"


@dataclass
class Candidate:
    id: str
    severity: str          # critical | high | medium | low
    attack_path: bool = False


@dataclass
class Exception:
    candidate_id: str
    reason: str
    approver: str
    expires: str           # ISO date


@dataclass
class GateResult:
    decision: str          # SHIP | BLOCK
    blockers: list[str]
    accepted: list[str]
    summary: str


def is_blocking(c: Candidate) -> bool:
    """A release blocker is a critical-risk finding or a real attack path."""
    return c.severity == "critical" or c.attack_path


def evaluate(candidates: list[Candidate], exceptions: Optional[list[Exception]] = None,
             *, today: Optional[date] = None) -> GateResult:
    today = today or date.today()
    valid_exc = {e.candidate_id for e in (exceptions or [])
                 if date.fromisoformat(e.expires) >= today}

    blockers, accepted = [], []
    for c in candidates:
        if is_blocking(c):
            (accepted if c.id in valid_exc else blockers).append(c.id)

    decision = BLOCK if blockers else SHIP
    summary = (f"{decision}: {len(blockers)} open blocker(s), "
               f"{len(accepted)} accepted via time-boxed exception")
    return GateResult(decision, blockers, accepted, summary)


def from_triage(findings) -> list[Candidate]:
    """Build gate candidates from triage findings. Blocking is driven by risk:
    a Critical band or an attack path becomes a critical candidate."""
    out = []
    for f in findings:
        sev = "critical" if f.risk_band() == "Critical" else f.vendor_severity
        out.append(Candidate(f.id, sev, f.is_attack_path()))
    return out


if __name__ == "__main__":
    cands = [
        Candidate("F1", "critical"),
        Candidate("F2", "high", attack_path=True),
        Candidate("F3", "medium"),
    ]
    exc = [Exception("F1", "compensating WAF rule in place", "ciso", "2026-12-31")]
    r = evaluate(cands, exc, today=date(2026, 6, 24))
    print(r.summary, "| blockers:", r.blockers, "| accepted:", r.accepted)
