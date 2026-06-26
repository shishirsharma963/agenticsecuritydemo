from datetime import datetime, timezone

from agentic_security import consent


def _reg():
    return consent.load_registry()


def test_data_loads():
    reg = _reg()
    assert len(reg) == 6


def test_opted_in_in_window_is_allowed():
    reg = _reg()
    # A. Rivera, opted_in, America/New_York -> 9am at 13:00 UTC.
    rivera = next(r for r in reg.values() if r.name.startswith("A."))
    send = consent.SMSSend(rivera.contact_id, "C",
                           datetime(2026, 6, 22, 13, 0, tzinfo=timezone.utc))
    assert consent.evaluate_send(send, reg).allowed is True


def test_opt_out_is_blocked():
    reg = _reg()
    optout = next(r for r in reg.values() if r.consent == "opted_out")
    send = consent.SMSSend(optout.contact_id, "C",
                           datetime(2026, 6, 22, 13, 0, tzinfo=timezone.utc))
    res = consent.evaluate_send(send, reg)
    assert res.allowed is False
    assert any("opted out" in r.lower() for r in res.reasons)


def test_no_consent_is_blocked():
    reg = _reg()
    none_rec = next(r for r in reg.values() if r.consent == "none")
    send = consent.SMSSend(none_rec.contact_id, "C",
                           datetime(2026, 6, 22, 13, 0, tzinfo=timezone.utc))
    assert consent.evaluate_send(send, reg).allowed is False


def test_quiet_hours_block_even_with_consent():
    reg = _reg()
    # C. Lindgren, opted_in, America/Los_Angeles -> 6am at 13:00 UTC (too early).
    west = next(r for r in reg.values() if r.timezone == "America/Los_Angeles")
    assert west.consent == "opted_in"
    early = consent.SMSSend(west.contact_id, "C",
                            datetime(2026, 6, 22, 13, 0, tzinfo=timezone.utc))
    assert consent.evaluate_send(early, reg).allowed is False
    # Same recipient at 17:00 UTC = 10am PT -> now allowed.
    ok = consent.SMSSend(west.contact_id, "C",
                         datetime(2026, 6, 22, 17, 0, tzinfo=timezone.utc))
    assert consent.evaluate_send(ok, reg).allowed is True


def test_evidence_never_carries_raw_id():
    reg = _reg()
    rec = next(iter(reg.values()))
    send = consent.SMSSend(rec.contact_id, "C",
                           datetime(2026, 6, 22, 13, 0, tzinfo=timezone.utc))
    ev = consent.evaluate_send(send, reg).evidence
    assert ev["contact_token"].startswith("tok_contact_")
    assert "TCPA" in ev["evidence_for"]
