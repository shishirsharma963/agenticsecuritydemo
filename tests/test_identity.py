import time

from agentic_security import identity
from agentic_security import governance as gov


def test_mint_verify_roundtrip():
    tok = identity.mint("alice", "human", "debug", "delivery-agent")
    claims = identity.verify(tok)
    assert claims["actor"] == "alice"
    assert claims["aud"] == "delivery-agent"


def test_tampered_token_is_rejected():
    tok = identity.mint("alice", "human", "debug", "delivery-agent")
    forged = tok[:-3] + ("aaa" if not tok.endswith("aaa") else "bbb")
    try:
        identity.verify(forged)
        assert False, "tampered token should not verify"
    except identity.TokenError:
        pass


def test_expired_token_is_rejected():
    past = int(time.time()) - 10_000
    tok = identity.mint("a", "human", "x", "guardrail", ttl=1, now=past)
    try:
        identity.verify(tok)
        assert False, "expired token should not verify"
    except identity.TokenError:
        pass


def test_verify_chain_ok_and_unsigned():
    hops = [("alice", "human", "debug"), ("delivery", "delivery-agent", "diagnose")]
    ok, chain, _ = identity.verify_chain(identity.mint_chain(hops))
    assert ok is True
    assert chain == ["human:alice", "delivery-agent:delivery"]
    assert identity.verify_chain(None)[0] is None


def test_guardrail_trusts_a_valid_chain():
    res = gov.process_request(gov.sample_request(), mode="good")
    assert res.chain_verified is True
    assert res.audit_record["chain_verified"] is True


def test_guardrail_blocks_a_forged_chain():
    hops = [("dev", "human", "summarize")]
    req = gov.AIRequest(
        prompt="Summarize this public press release.",
        actor_chain=[gov.AgentHop(*hops[0])],
        destination="amazon-bedrock",
        chain_tokens=[identity.mint_chain(hops)[0][:-2] + "zz"],  # tamper signature
    )
    res = gov.process_request(req, mode="good")
    assert res.chain_verified is False
    assert res.allowed is False
    assert any("identity" in d.reason.lower() for d in res.decisions)


def test_unsigned_request_is_not_blocked_for_identity():
    req = gov.AIRequest(
        prompt="Summarize this public press release.",
        actor_chain=[gov.AgentHop("dev", "human", "summarize")],
        destination="amazon-bedrock",
    )
    res = gov.process_request(req, mode="good")
    assert res.chain_verified is None
    assert res.allowed is True
