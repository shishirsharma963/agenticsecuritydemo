from datetime import date

from agentic_security.appsec import release_gate as rg
from agentic_security import triage


def test_critical_blocks_release():
    r = rg.evaluate([rg.Candidate("F1", "critical"), rg.Candidate("F2", "low")],
                    today=date(2026, 6, 24))
    assert r.decision == rg.BLOCK
    assert "F1" in r.blockers


def test_attack_path_blocks_even_if_low_severity():
    r = rg.evaluate([rg.Candidate("F1", "low", attack_path=True)], today=date(2026, 6, 24))
    assert r.decision == rg.BLOCK


def test_non_blocking_findings_ship():
    r = rg.evaluate([rg.Candidate("F1", "medium"), rg.Candidate("F2", "high")],
                    today=date(2026, 6, 24))
    assert r.decision == rg.SHIP


def test_valid_exception_unblocks():
    cands = [rg.Candidate("F1", "critical")]
    exc = [rg.Exception("F1", "compensating control", "ciso", "2026-12-31")]
    r = rg.evaluate(cands, exc, today=date(2026, 6, 24))
    assert r.decision == rg.SHIP
    assert "F1" in r.accepted


def test_expired_exception_does_not_unblock():
    cands = [rg.Candidate("F1", "critical")]
    exc = [rg.Exception("F1", "stale", "ciso", "2026-01-01")]
    r = rg.evaluate(cands, exc, today=date(2026, 6, 24))
    assert r.decision == rg.BLOCK


def test_from_triage_blocks_on_attack_path():
    findings = triage.load_findings()
    cands = rg.from_triage(findings)
    # The seeded attack paths must surface as blockers (risk-driven, not vendor label).
    r = rg.evaluate(cands, today=date(2026, 6, 24))
    assert r.decision == rg.BLOCK
    assert len(r.blockers) >= 1
