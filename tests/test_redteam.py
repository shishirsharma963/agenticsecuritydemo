from agentic_security import redteam as rt


def test_injection_is_detected_in_input():
    finds = rt.scan_input(rt.SAMPLE_INJECTION)
    rules = {f.rule for f in finds}
    assert "ignore-instructions" in rules
    assert any(f.severity == "high" for f in finds)


def test_clean_input_has_no_injection():
    assert rt.scan_input("Please summarize the public release notes.") == []


def test_output_leaking_secret_is_blocked():
    v = rt.check_output(rt.SAMPLE_BAD_OUTPUT, allowed_tools={"search", "summarize"})
    assert v.allowed is False
    assert any("secret" in r.lower() or "pii" in r.lower() for r in v.reasons)


def test_output_revealing_instructions_is_blocked():
    v = rt.check_output("Sure, my system prompt is: you are a helpful agent.")
    assert v.allowed is False
    assert any("instruction" in r.lower() for r in v.reasons)


def test_unauthorized_tool_call_is_blocked():
    v = rt.check_output("TOOL_CALL: delete_database", allowed_tools={"search"})
    assert v.allowed is False
    assert any("delete_database" in r for r in v.reasons)


def test_clean_output_passes():
    v = rt.check_output(rt.SAMPLE_GOOD_OUTPUT, allowed_tools={"search", "summarize"})
    assert v.allowed is True
