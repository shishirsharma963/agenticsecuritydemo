"""Per-hop signed identity for the agent chain.

Each hop in `user -> agent -> agent` carries a short-lived token signed by a
shared key and scoped to the next hop. The guardrail verifies the whole chain
before it trusts the provenance it writes to the audit record, so "who, through
which agents" is proven rather than asserted.

Stdlib HMAC keeps the demo zero-install. The production version uses RS256 JWTs
minted by an STS and verified at a gateway that holds only the public key; that
is the sibling agentidentity repo, built to the same shape so the two compose.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

# Signing key for the demo. In production this is asymmetric: the STS signs with a
# private key and the gateway verifies with the public key, so the gateway can
# check tokens but never mint them. Here both sides share one HMAC key.
_SIGNING_KEY = b"agenticsecuritydemo-sts-key-not-a-real-secret"
DEFAULT_TTL = 300  # seconds


class TokenError(Exception):
    """Raised when a token is malformed, mis-signed, or expired."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(body: str) -> str:
    return _b64(hmac.new(_SIGNING_KEY, body.encode(), hashlib.sha256).digest())


def mint(actor: str, role: str, intent: str, audience: str,
         *, ttl: int = DEFAULT_TTL, now: Optional[int] = None) -> str:
    """Mint one hop's token, scoped (`aud`) to the next hop."""
    now = now if now is not None else int(time.time())
    payload = {"actor": actor, "role": role, "intent": intent,
               "aud": audience, "iat": now, "exp": now + ttl}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{body}.{_sign(body)}"


def verify(token: str, *, now: Optional[int] = None) -> dict:
    """Return the claims if the token is well-formed, correctly signed, and
    unexpired; otherwise raise TokenError."""
    now = now if now is not None else int(time.time())
    try:
        body, sig = token.split(".")
    except ValueError:
        raise TokenError("malformed token")
    # constant-time compare so a wrong signature can't be timing-probed
    if not hmac.compare_digest(sig, _sign(body)):
        raise TokenError("bad signature")
    claims = json.loads(_unb64(body))
    if claims["exp"] < now:
        raise TokenError("expired")
    return claims


def mint_chain(hops: list[tuple[str, str, str]], *, now: Optional[int] = None) -> list[str]:
    """Mint a token per hop. hops = [(actor, role, intent), ...]; each token is
    scoped to the next hop's role, the last to the guardrail itself."""
    tokens = []
    for i, (actor, role, intent) in enumerate(hops):
        audience = hops[i + 1][1] if i + 1 < len(hops) else "guardrail"
        tokens.append(mint(actor, role, intent, audience, now=now))
    return tokens


def verify_chain(tokens: Optional[list[str]], *, now: Optional[int] = None):
    """Verify every hop. Returns (verified, chain, reason):
      verified is None  -> no identity was presented (unsigned request)
      verified is True  -> every hop's token checked out
      verified is False -> a hop failed (tampered / expired / forged)"""
    if not tokens:
        return None, [], "no signed identity presented"
    chain: list[str] = []
    for t in tokens:
        try:
            claims = verify(t, now=now)
        except TokenError as e:
            return False, chain, f"chain verification failed: {e}"
        chain.append(f"{claims['role']}:{claims['actor']}")
    return True, chain, "all hops verified"
