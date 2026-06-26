from agentic_security.detection import autoresponse as ar


def test_high_severity_cred_exfil_triggers_destructive_actions():
    actions = ar.respond({
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.0, "resource": "AKIA / i-0abc"})
    names = {a.action for a in actions}
    assert "disable_iam_key" in names
    assert "isolate_instance" in names
    assert ar.took_destructive_action(actions) is True
    # Always also opens an incident and notifies.
    assert "open_incident" in names and "notify" in names


def test_known_type_below_threshold_is_alert_only():
    actions = ar.respond({
        "type": "UnauthorizedAccess:IAMUser/ConsoleLogin",
        "severity": 3.0, "resource": "user/bob"})
    assert ar.took_destructive_action(actions) is False
    assert any(a.action == "alert" for a in actions)


def test_unknown_type_never_destructive():
    actions = ar.respond({"type": "Recon:Something/Novel", "severity": 9.0,
                          "resource": "x"})
    assert ar.took_destructive_action(actions) is False
    assert any(a.action == "alert" for a in actions)


def test_s3_public_revokes_access():
    actions = ar.respond({
        "type": "Policy:S3/BucketPublicAccessGranted", "severity": 7.5,
        "resource": "arn:aws:s3:::prod"})
    assert any(a.action == "revoke_public_access" for a in actions)


def test_actions_are_well_formed():
    for a in ar.respond(ar.SAMPLE_FINDING):
        assert a.action and a.target and a.reason
        assert isinstance(a.destructive, bool)
        if a.destructive:
            assert a.action in ar.DESTRUCTIVE
