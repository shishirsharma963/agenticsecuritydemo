"""TCPA SMS-consent guardrail.

A business that texts customers falls under the TCPA: you may only text someone
who gave prior express consent, you must honor an opt-out (STOP) immediately, and
you may only contact them in their local 8am to 9pm window. Each violation is a
per-message liability ($500 to $1,500), so the check belongs in the send path.

This is a regulated-industry control, not a domain-specific one: TCPA covers any
consumer SMS (retail, fintech, healthcare), and email has parallel regimes
(CAN-SPAM, GDPR/CCPA consent). Swap "SMS send" for "any outbound message".

    bad : blast the campaign to every contact on the list.
    good: each send is checked against consent, opt-out, and quiet hours, then
          allowed or blocked with a TCPA evidence record.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

# TCPA "quiet hours": no marketing contact before 8am or after 9pm local to the
# recipient. Local time matters: a 1pm UTC blast is 6am on the West Coast.
QUIET_START = 8     # local hour, inclusive
QUIET_END = 21      # local hour, exclusive (9:00pm)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "contacts_consent.json"


@dataclass
class ConsentRecord:
    contact_id: str
    name: str
    timezone: str                 # IANA tz, e.g. "America/New_York"
    consent: str                  # "opted_in" | "opted_out" | "none"
    consent_date: Optional[str] = None


@dataclass
class SMSSend:
    contact_id: str
    campaign: str
    when: datetime                # UTC instant the send would go out


@dataclass
class ConsentResult:
    allowed: bool
    reasons: list[str]
    evidence: dict


def load_registry(path: Path = DATA_FILE) -> dict[str, ConsentRecord]:
    raw = json.loads(Path(path).read_text())
    return {r["contact_id"]: ConsentRecord(**r) for r in raw}


def _contact_token(contact_id: str) -> str:
    # Even in the consent record we don't carry the raw identifier into evidence.
    return "tok_contact_" + hashlib.sha256(contact_id.encode()).hexdigest()[:8]


def evaluate_send(send: SMSSend, registry: dict[str, ConsentRecord],
                  *, now: Optional[datetime] = None) -> ConsentResult:
    """Allow or block a single SMS send, with the reasons and an evidence record."""
    rec = registry.get(send.contact_id)
    reasons: list[str] = []
    allowed = True

    # 1. Consent must exist and be affirmative.
    if rec is None or rec.consent == "none":
        allowed = False
        reasons.append("no prior express consent on file (TCPA)")
    elif rec.consent == "opted_out":
        allowed = False
        reasons.append("recipient sent STOP, opted out; further contact prohibited")

    # 2. Even with consent, respect the local quiet-hours window.
    if rec is not None:
        local = send.when.astimezone(ZoneInfo(rec.timezone))
        if not (QUIET_START <= local.hour < QUIET_END):
            allowed = False
            reasons.append(
                f"outside 8am to 9pm local window ({local.strftime('%H:%M')} {rec.timezone})")

    if allowed:
        reasons.append("express consent on file; within local calling window")

    evidence = {
        "contact_token": _contact_token(send.contact_id),   # never the raw id
        "campaign": send.campaign,
        "decision": "ALLOW" if allowed else "BLOCK",
        "reasons": reasons,
        "control": "tcpa-sms-consent",
        "evidence_for": ["TCPA", "SOC2-CC6.3"],
        "evaluated_at": (now or datetime.now(timezone.utc)).isoformat(),
    }
    return ConsentResult(allowed, reasons, evidence)


def bad_state_summary() -> str:
    return ("The campaign blasts every contact on the list, no consent check, no "
            "opt-out honored, no quiet-hours. A single STOP-list miss or a 2am "
            "text is a TCPA violation at $500 to $1,500 per message.")


# --------------------------------------------------------------------------- #
# Synthetic data generator (seeded, reproducible)                              #
# --------------------------------------------------------------------------- #
# A spread that produces a mix of outcomes at the demo's send time (13:00 UTC):
# East-coast opted-in = 9am (allowed); West-coast opted-in = 6am (quiet hours);
# plus an opt-out and a no-consent record.
_SEED_RECORDS = [
    ("CUST-1001", "A. Rivera",   "America/New_York",    "opted_in"),
    ("CUST-1002", "B. Okafor",   "America/Chicago",     "opted_in"),
    ("CUST-1003", "C. Lindgren", "America/Los_Angeles", "opted_in"),
    ("CUST-1004", "D. Patel",    "America/New_York",    "opted_out"),
    ("CUST-1005", "E. Nguyen",   "America/Denver",      "none"),
    ("CUST-1006", "F. Santos",   "America/New_York",    "opted_in"),
]


def write_data(path: Path = DATA_FILE) -> int:
    rnd = random.Random(7)
    records = []
    for cid, name, tz, consent in _SEED_RECORDS:
        records.append(asdict(ConsentRecord(
            contact_id=cid, name=name, timezone=tz, consent=consent,
            consent_date=None if consent == "none"
            else f"2026-0{rnd.randint(1,5)}-1{rnd.randint(0,9)}")))
    Path(path).write_text(json.dumps(records, indent=2))
    return len(records)


def sample_sends(registry: dict[str, ConsentRecord],
                 when: Optional[datetime] = None) -> list[SMSSend]:
    when = when or datetime(2026, 6, 22, 13, 0, tzinfo=timezone.utc)  # 13:00 UTC
    return [SMSSend(contact_id=cid, campaign="Brand_X_Outreach", when=when) for cid in registry]


if __name__ == "__main__":
    n = write_data()
    print(f"wrote {n} synthetic consent records to {DATA_FILE}")
