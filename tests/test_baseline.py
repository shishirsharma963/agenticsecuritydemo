from agentic_security.cloud import baseline
from agentic_security import threatmodel as tm


def test_render_scp_is_a_valid_deny_policy():
    doc = baseline.render_scp(baseline.SCPS[0])
    assert doc["Version"] == "2012-10-17"
    stmt = doc["Statement"][0]
    assert stmt["Effect"] == "Deny"
    assert stmt["Action"] and stmt["Resource"] == "*"


def test_every_scp_prevents_a_real_threat():
    # Cross-module check: an SCP may only claim to prevent a threat that exists.
    threat_ids = {t.id for t in tm.THREATS}
    for scp in baseline.SCPS:
        assert scp.prevents in threat_ids, f"{scp.id} prevents unknown threat {scp.prevents}"


def test_terraform_config_rule_renders():
    hcl = baseline.render_terraform_config_rule(baseline.CONFIG_RULES[0])
    assert 'resource "aws_config_config_rule"' in hcl
    assert "source_identifier" in hcl
    assert baseline.CONFIG_RULES[0].name in hcl


def test_evaluate_flags_drift_and_clean_passes():
    nc = baseline.noncompliant(baseline.SAMPLE_ACCOUNT)
    names = {c.rule for c in nc}
    assert "S3_BUCKET_PUBLIC_READ_PROHIBITED" in names
    assert "ENCRYPTED_VOLUMES" in names
    assert all(c.status == "NON_COMPLIANT" for c in nc)
    # A clean account state produces zero non-compliant rules.
    assert baseline.noncompliant({}) == []


def test_config_rule_state_keys_are_unique():
    keys = [r.state_key for r in baseline.CONFIG_RULES]
    assert len(keys) == len(set(keys))
