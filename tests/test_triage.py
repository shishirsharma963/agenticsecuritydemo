from agentic_security import triage


def test_findings_load():
    findings = triage.load_findings()
    assert len(findings) == 240


def test_attack_paths_score_highest():
    findings = triage.load_findings()
    ranked = triage.risk_view(findings)
    # The top finding must be a real attack path.
    assert ranked[0].is_attack_path()
    # And it must out-score the first non-attack-path finding.
    first_non_path = next(f for f in ranked if not f.is_attack_path())
    assert ranked[0].risk_score() > first_non_path.risk_score()


def test_vendor_view_disagrees_with_risk_view():
    # Sorting by vendor severity is not the same as sorting by risk.
    findings = triage.load_findings()
    vendor_top = triage.vendor_view(findings)[0]
    risk_top = triage.risk_view(findings)[0]
    assert vendor_top.id != risk_top.id


def test_score_weights_are_additive():
    f = triage.Finding(
        id="x", title="t", resource="r", vendor_severity="low",
        internet_facing=True, sensitive_data=True)
    assert f.risk_score() == triage.WEIGHTS["internet_facing"] + triage.WEIGHTS["sensitive_data"]


def test_dedupe_collapses_duplicates():
    dup = triage.Finding(id="a", title="Public S3", resource="bucket-1", vendor_severity="high")
    same = triage.Finding(id="b", title="Public S3", resource="bucket-1", vendor_severity="high")
    other = triage.Finding(id="c", title="Public S3", resource="bucket-2", vendor_severity="high")
    out = triage.dedupe([dup, same, other])
    assert len(out) == 2   # same title+resource collapses; different resource stays
