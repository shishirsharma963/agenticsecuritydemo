from pathlib import Path

from agentic_security import scanner

ROOT = Path(__file__).resolve().parent.parent


def test_bad_app_has_high_findings():
    fs = scanner.scan_file(ROOT / "lab" / "app_bad.py")
    rules = {f.rule for f in fs}
    assert "hardcoded-aws-key" in rules
    assert "sql-string-concat" in rules
    assert "unauthenticated-endpoint" in rules
    assert "flask-debug-true" in rules
    assert scanner.summarize(fs)["high"] >= 3


def test_good_app_is_clean():
    fs = scanner.scan_file(ROOT / "lab" / "app_good.py")
    # This is the CI gate: the hardened app must produce zero high findings.
    assert scanner.summarize(fs)["high"] == 0


def test_secret_is_detected():
    fs = scanner.scan_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
    assert any(f.rule == "hardcoded-aws-key" for f in fs)
