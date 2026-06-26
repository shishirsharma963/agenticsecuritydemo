from agentic_security.appsec import connectors as c


def test_granted_action_is_allowed():
    d = c.authorize("user:alice", "email", "send", c.SAMPLE_GRANTS)
    assert d.allowed is True


def test_least_privilege_denies_ungranted_scope():
    # agent:outreach has crm read, not export.
    d = c.authorize("agent:outreach", "crm", "export", c.SAMPLE_GRANTS)
    assert d.allowed is False
    assert "export" in d.reason


def test_no_grant_is_denied():
    d = c.authorize("agent:outreach", "prod_db", "write", c.SAMPLE_GRANTS)
    assert d.allowed is False
    assert "no grant" in d.reason.lower()


def test_high_risk_action_is_flagged():
    d = c.authorize("agent:outreach", "prod_db", "write", c.SAMPLE_GRANTS)
    assert d.high_risk is True


def test_anomalous_first_time_access_is_flagged():
    seen = {("user:alice", "email")}
    d = c.authorize("user:alice", "calendar", "read", c.SAMPLE_GRANTS, seen=seen)
    assert d.anomalous is True


def test_audit_never_carries_raw_principal():
    d = c.authorize("user:alice", "email", "send", c.SAMPLE_GRANTS)
    assert d.audit["principal_token"].startswith("tok_")
    assert "user:alice" not in str(d.audit)
    assert "SOC2-CC6.1" in d.audit["evidence_for"]


def test_unknown_connector_is_denied():
    d = c.authorize("user:alice", "wat", "read", c.SAMPLE_GRANTS)
    assert d.allowed is False
