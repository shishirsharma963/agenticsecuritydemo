from agentic_security import governance as gov


def test_secret_is_blocked():
    res = gov.process_request(gov.sample_request(), mode="good")
    actions = [d.action for d in res.decisions]
    assert gov.Action.BLOCK in actions
    assert res.allowed is False
    assert "[BLOCKED:secret]" in res.sanitized_prompt
    assert "AKIAIOSFODNN7EXAMPLE" not in res.sanitized_prompt


def test_secret_reported_once_not_per_rule():
    # The AKIA key sits inside an aws_secret_access_key= assignment, so two rules
    # match the same secret. It must be reported once, naming both rules.
    dets = gov.classify(gov.SAMPLE_RISKY_PROMPT)
    secrets = [d for d in dets if d.data_class == gov.DataClass.SECRET]
    assert len(secrets) == 1
    assert "+" in secrets[0].reason


def test_pii_card_is_tokenized_not_leaked():
    res = gov.process_request(gov.sample_request(), mode="good")
    # The raw card must not survive into the prompt that leaves the boundary.
    assert "4111 1111 1111 1111" not in res.sanitized_prompt
    assert "4111111111111111" not in res.sanitized_prompt.replace(" ", "")
    assert any(t.startswith("tok_pii_") for t in res.token_vault)


def test_valid_card_is_high_confidence():
    dets = gov.classify("payment Card: 4111 1111 1111 1111")
    pii = [d for d in dets if d.data_class == gov.DataClass.PII]
    assert pii and pii[0].confidence == "high"


def test_unapproved_destination_is_rerouted():
    res = gov.process_request(gov.sample_request("public-llm-chatbot"), mode="good")
    assert any(d.action == gov.Action.ROUTE for d in res.decisions)


def test_clean_prompt_is_allowed():
    req = gov.AIRequest(
        prompt="Summarize this public press release about our product.",
        actor_chain=[gov.AgentHop("dev", "human", "summarize")],
        destination="amazon-bedrock",
    )
    res = gov.process_request(req, mode="good")
    assert res.allowed is True
    assert res.detections == []


def test_bad_mode_has_no_controls():
    res = gov.process_request(gov.sample_request(), mode="bad")
    assert res.allowed is True
    assert res.detections == []
    assert "AKIAIOSFODNN7EXAMPLE" in res.sanitized_prompt


def test_audit_record_is_emitted_in_good_mode():
    res = gov.process_request(gov.sample_request(), mode="good")
    rec = res.audit_record
    assert rec["actor_chain"][0].startswith("human:")
    assert rec["cost_center"] == "eng-platform"
    assert "SOC2-CC6.1" in rec["evidence_for"]
