from agentic_security import threatmodel as tm


def test_every_threat_maps_to_a_real_control():
    # The whole point of the model-as-data: a threat may only claim a control that
    # actually exists in the repo. This fails if someone adds a paper mitigation.
    for t in tm.THREATS:
        assert t.control in tm.VALID_CONTROLS, f"{t.id} claims unknown control {t.control}"


def test_threats_are_well_formed():
    ids = [t.id for t in tm.THREATS]
    assert len(ids) == len(set(ids)), "duplicate threat ids"
    for t in tm.THREATS:
        assert t.stride in tm.STRIDE
        assert t.status in tm.STATUS
        assert t.mitigation and t.description


def test_all_stride_categories_are_covered():
    covered = {t.stride for t in tm.THREATS}
    assert covered == tm.STRIDE, f"missing STRIDE categories: {tm.STRIDE - covered}"


def test_coverage_and_gaps_agree():
    cov = tm.coverage()
    assert cov["total"] == len(tm.THREATS)
    assert sum(cov["by_status"].values()) == cov["total"]
    assert len(tm.gaps()) == cov["by_status"]["partial"] + cov["by_status"]["accepted"]
