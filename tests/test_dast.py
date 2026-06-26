from agentic_security.appsec import dast


def test_bad_target_is_caught():
    fs = dast.probe(dast.bad_target)
    rules = {f.rule for f in fs}
    assert "missing-authentication" in rules
    assert "missing-security-headers" in rules
    assert "error-leakage" in rules
    assert dast.summarize(fs)["high"] >= 1


def test_good_target_is_clean():
    # CI gate: the hardened target must produce zero findings.
    fs = dast.probe(dast.good_target)
    assert dast.summarize(fs)["total"] == 0


def test_unauth_on_each_protected_route():
    fs = dast.probe(dast.bad_target)
    flagged = {f.endpoint for f in fs if f.rule == "missing-authentication"}
    assert set(dast.PROTECTED) <= flagged
