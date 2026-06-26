"""AI prompt/data governance guardrail.

A control plane around an agentic AI platform that handles regulated data:
classify what a prompt contains, decide a policy action, tokenize sensitive
fields, carry a verified agent identity and per-hop intent, and emit one audit
record. The classifiers, the Luhn check, and the tokenization vault run for real;
the data is synthetic.

    BAD  : prompt -> agent -> model, raw. No classification, no identity,
           no audit, untracked spend.
    GOOD : prompt intercepted -> classified -> policy decision -> sensitive
           fields tokenized -> identity verified -> cost attributed -> audit.

The destination registry covers the AI tools a team actually uses (Anthropic,
OpenAI, Amazon Bedrock, Cursor) and routes regulated data only to endpoints under
a data-processing agreement. The pattern is domain-neutral: the same guardrail
protects PHI in healthcare, cardholder data under PCI in fintech/retail, or PII
under GDPR/CCPA anywhere. Classifiers here are deterministic regex; production
would use a DLP engine. The actor chain is verified per hop (see identity.py): a
forged or expired chain is blocked. The production-grade identity layer (RS256
JWTs from an STS) is the sibling agentidentity repo.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from agentic_security import identity


# --------------------------------------------------------------------------- #
# Data classes                                                                 #
# --------------------------------------------------------------------------- #
class DataClass(str, Enum):
    SECRET = "secret"               # API keys, private keys -> always block
    PII = "pii"                     # payment cards (Luhn), SSNs, direct identifiers
    SENSITIVE_RECORD = "sensitive"  # fraud/medical/financial notes about a person
    CUSTOMER_CONTEXT = "customer"   # account / customer / campaign identifiers
    PRODUCTION_LOG = "prod_log"     # stack traces / production error logs
    SOURCE_CODE = "source_code"     # source snippets


class Action(str, Enum):
    BLOCK = "BLOCK"                  # do not let the request proceed
    REDACT = "REDACT"               # tokenize the field, then proceed
    ROUTE = "ROUTE"                 # only to an approved/covered destination
    LOG = "LOG"                     # write SOC 2 / AI-usage evidence
    TICKET = "TICKET"               # open remediation work (e.g. rotate secret)
    ALLOW = "ALLOW"                 # nothing sensitive, proceed


@dataclass
class Detection:
    data_class: DataClass
    snippet: str                    # the matched text (pre-tokenization)
    confidence: str                 # "high" | "medium"
    reason: str


@dataclass
class AgentHop:
    """One link in the user -> agent -> agent actor chain."""
    actor: str
    role: str                       # "human" | "delivery-agent" | "retrieval-agent"
    intent: str


@dataclass
class AIRequest:
    prompt: str
    actor_chain: list[AgentHop]
    destination: str                # tool id, e.g. "anthropic-enterprise"
    cost_center: str = "unattributed"
    # Per-hop signed identity tokens (see identity.mint_chain). Optional: when
    # absent the request is treated as unsigned; when present it is verified and a
    # forged/expired chain is blocked.
    chain_tokens: Optional[list[str]] = None


@dataclass
class Decision:
    action: Action
    data_class: Optional[DataClass]
    reason: str


@dataclass
class GovernanceResult:
    mode: str                       # "bad" | "good"
    request_id: str
    allowed: bool
    detections: list[Detection]
    decisions: list[Decision]
    sanitized_prompt: str
    token_vault: dict[str, str]     # token -> original (the re-identification vault)
    audit_record: dict
    est_tokens: int
    est_cost_usd: float
    chain_verified: Optional[bool] = None   # None = unsigned, True/False = checked


# --------------------------------------------------------------------------- #
# Approved-tool registry (data-handling posture)                               #
# --------------------------------------------------------------------------- #
# A real deployment's AI tool inventory: enterprise account, SSO, training opt-out,
# and a data-processing agreement (DPA/BAA) for regulated data. `dpa=True` means
# the vendor is contractually cleared to process regulated data.
APPROVED_TOOLS: dict[str, dict] = {
    "anthropic-enterprise": {"approved": True, "zero_retention": True, "dpa": True},
    "openai-enterprise": {"approved": True, "zero_retention": True, "dpa": True},
    "amazon-bedrock": {"approved": True, "zero_retention": True, "dpa": True},
    "cursor": {"approved": True, "zero_retention": True, "dpa": False},
    # Unapproved / consumer endpoints: no DPA, prompts may train the model.
    "chatgpt-consumer": {"approved": False, "zero_retention": False, "dpa": False},
    "public-paste-llm": {"approved": False, "zero_retention": False, "dpa": False},
}

# Rough public list price (USD per 1K tokens) for spend attribution demo only.
PRICE_PER_1K_TOKENS = 0.015


# --------------------------------------------------------------------------- #
# Classifiers (real, deterministic)                                            #
# --------------------------------------------------------------------------- #
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Bearer / API token", re.compile(r"(?i)\b(?:api[_-]?key|bearer|secret)\s*[=:]\s*[A-Za-z0-9/\+_\-]{16,}")),
]

# Candidate card-like runs (13-19 digits, spaces/dashes allowed) and SSNs.
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

_SENSITIVE_TERMS = re.compile(
    r"(?i)\b(fraud|flagged|salary|payroll|medical|diagnos|credit limit|"
    r"background check|termination|internal note|patient)\w*"
)
_CUSTOMER_TERMS = re.compile(r"(?i)\b(account|customer|campaign|tenant|subscriber)\w*")
_PROD_LOG_TERMS = re.compile(
    r"(?i)(traceback|stack trace|at\s+\w+\.\w+\(|exception in thread|\bERROR\b.*\bprod)"
)
_SOURCE_TERMS = re.compile(
    r"(def\s+\w+\(|function\s+\w+\(|class\s+\w+[:\(]|import\s+\w+|SELECT\s+.+\s+FROM\s+)"
)


def is_valid_luhn(number: str) -> bool:
    """Standard Luhn checksum, the real algorithm behind payment-card numbers.
    Used to flag a digit run as a likely card with high (not guessed) confidence."""
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        total += sum(divmod(d * 2, 10)) if i % 2 == 1 else d
    return total % 10 == 0


def _merge_spans(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, list[str]]]:
    """Merge overlapping/adjacent (start, end, label) spans into one, collecting
    the labels. Stops one underlying secret from being reported once per rule
    that happens to match it (e.g. an AKIA key inside an `aws_secret_access_key=`
    assignment)."""
    if not spans:
        return []
    spans = sorted(spans)
    cs, ce, clabels = spans[0][0], spans[0][1], [spans[0][2]]
    merged: list[tuple[int, int, list[str]]] = []
    for s, e, lab in spans[1:]:
        if s <= ce:
            ce = max(ce, e)
            if lab not in clabels:
                clabels.append(lab)
        else:
            merged.append((cs, ce, clabels))
            cs, ce, clabels = s, e, [lab]
    merged.append((cs, ce, clabels))
    return merged


def classify(text: str) -> list[Detection]:
    """Return every sensitive thing found in a prompt. Order: most severe first."""
    out: list[Detection] = []

    # Secrets: collect every rule hit, then merge overlapping matches.
    secret_spans = [(m.start(), m.end(), label)
                    for label, pat in _SECRET_PATTERNS
                    for m in pat.finditer(text)]
    for start, end, labels in _merge_spans(secret_spans):
        out.append(Detection(DataClass.SECRET, text[start:end], "high",
                             f"{' + '.join(labels)} present in prompt"))

    # PII: Luhn-valid card numbers (high) and SSNs (high).
    for m in _CARD_RE.finditer(text):
        if is_valid_luhn(m.group(0)):
            out.append(Detection(DataClass.PII, m.group(0).strip(), "high",
                                 "Luhn-valid payment card number"))
    for m in _SSN_RE.finditer(text):
        out.append(Detection(DataClass.PII, m.group(0), "high", "SSN pattern"))

    if _SENSITIVE_TERMS.search(text):
        out.append(Detection(DataClass.SENSITIVE_RECORD,
                             _SENSITIVE_TERMS.search(text).group(0), "medium",
                             "sensitive record / note about a person"))
    if _CUSTOMER_TERMS.search(text):
        out.append(Detection(DataClass.CUSTOMER_CONTEXT,
                             _CUSTOMER_TERMS.search(text).group(0), "medium",
                             "customer / account context"))
    if _PROD_LOG_TERMS.search(text):
        out.append(Detection(DataClass.PRODUCTION_LOG,
                             _PROD_LOG_TERMS.search(text).group(0)[:40], "medium",
                             "production log / stack trace"))
    if _SOURCE_TERMS.search(text):
        out.append(Detection(DataClass.SOURCE_CODE,
                             _SOURCE_TERMS.search(text).group(0)[:40], "medium",
                             "source-code context"))

    severity_order = {
        DataClass.SECRET: 0, DataClass.PII: 1, DataClass.SENSITIVE_RECORD: 2,
        DataClass.CUSTOMER_CONTEXT: 3, DataClass.PRODUCTION_LOG: 4, DataClass.SOURCE_CODE: 5,
    }
    return sorted(out, key=lambda d: severity_order[d.data_class])


# --------------------------------------------------------------------------- #
# Tokenization vault                                                            #
# --------------------------------------------------------------------------- #
def _token_for(data_class: DataClass, value: str) -> str:
    """Deterministic token for a sensitive value; the mapping lives in the vault,
    not in the outgoing prompt. Truncated SHA-256 here (collisions possible,
    vault in memory); production would use envelope encryption via a
    key-management service (e.g. AWS KMS) and format-preserving tokenization."""
    digest = hashlib.sha256(f"{data_class.value}:{value}".encode()).hexdigest()[:8]
    return f"tok_{data_class.value}_{digest}"


# --------------------------------------------------------------------------- #
# Policy engine                                                                 #
# --------------------------------------------------------------------------- #
def _decide(detections: list[Detection], destination: str) -> list[Decision]:
    decisions: list[Decision] = []
    tool = APPROVED_TOOLS.get(destination, {"approved": False, "dpa": False})

    has_secret = any(d.data_class == DataClass.SECRET for d in detections)
    sensitive = [d for d in detections if d.data_class in (
        DataClass.PII, DataClass.SENSITIVE_RECORD, DataClass.CUSTOMER_CONTEXT)]

    # A secret can't be un-leaked once it crosses the boundary, so it
    # short-circuits everything: block now, rotate later.
    if has_secret:
        decisions.append(Decision(Action.BLOCK, DataClass.SECRET,
                                  "Secret detected; request blocked at the boundary"))
        decisions.append(Decision(Action.TICKET, DataClass.SECRET,
                                  "Open secret-rotation ticket; secret is now considered exposed"))

    # Sensitive but recoverable data is tokenized, not blocked, so the work can
    # still go through without the raw identifier attached.
    for d in sensitive:
        decisions.append(Decision(Action.REDACT, d.data_class,
                                  f"Tokenize {d.data_class.value} into a non-identifiable unit"))

    # Destination is a separate check from content: an unapproved tool is never
    # acceptable; an approved-but-not-DPA tool is fine for non-regulated data but
    # not for PII or other regulated records.
    if not tool["approved"]:
        decisions.append(Decision(Action.ROUTE, None,
                                  f"Destination '{destination}' is not an approved AI tool; "
                                  f"route to an approved, covered endpoint"))
    elif sensitive and not tool.get("dpa"):
        decisions.append(Decision(Action.ROUTE, None,
                                  f"'{destination}' is approved but not DPA-covered; "
                                  f"regulated data requires a DPA-covered destination"))

    # If anything was detected, always leave a record. That record is what makes
    # the control auditable after the fact.
    if detections:
        decisions.append(Decision(Action.LOG, None,
                                  "Write AI-usage / SOC 2 evidence record"))
    if not decisions:
        decisions.append(Decision(Action.ALLOW, None, "No sensitive data; allowed"))
    return decisions


# --------------------------------------------------------------------------- #
# Spend attribution                                                             #
# --------------------------------------------------------------------------- #
def _estimate_cost(text: str) -> tuple[int, float]:
    tokens = max(1, len(text) // 4)
    return tokens, round(tokens / 1000 * PRICE_PER_1K_TOKENS, 4)


# --------------------------------------------------------------------------- #
# The guardrail                                                                 #
# --------------------------------------------------------------------------- #
def process_request(req: AIRequest, mode: str, *, now: Optional[datetime] = None) -> GovernanceResult:
    now = now or datetime.now(timezone.utc)
    request_id = f"air_{uuid.uuid4().hex[:10]}"
    est_tokens, est_cost = _estimate_cost(req.prompt)
    chain = [f"{h.role}:{h.actor}" for h in req.actor_chain]

    if mode == "bad":
        # No control plane: the prompt goes straight to the model. The result is
        # still built so the demo can show what was skipped (no classification,
        # no identity, no audit, unattributed spend).
        return GovernanceResult(
            mode="bad", request_id=request_id, allowed=True,
            detections=[], decisions=[Decision(Action.ALLOW, None, "no control plane")],
            sanitized_prompt=req.prompt, token_vault={},
            audit_record={"note": "no audit emitted in bad state"},
            est_tokens=est_tokens, est_cost_usd=est_cost,
        )

    detections = classify(req.prompt)
    decisions = _decide(detections, req.destination)

    # Verify the agent identity chain before trusting it. An unsigned request is
    # allowed through and recorded as such; a forged or expired chain is blocked,
    # so the audit record never carries provenance that wasn't proven.
    chain_verified, _vchain, chain_reason = identity.verify_chain(req.chain_tokens)
    if chain_verified is False:
        decisions.append(Decision(Action.BLOCK, None,
                                  f"Agent identity failed verification; {chain_reason}"))

    # Rewrite the prompt so the version that leaves the boundary is safe: secrets
    # are removed, everything else is swapped for a vault token. Raw values live
    # only in the vault, never in the outgoing prompt.
    sanitized = req.prompt
    vault: dict[str, str] = {}
    for d in detections:
        if d.data_class == DataClass.SECRET:
            sanitized = sanitized.replace(d.snippet, "[BLOCKED:secret]")
        else:
            tok = _token_for(d.data_class, d.snippet)
            vault[tok] = d.snippet
            sanitized = sanitized.replace(d.snippet, tok)

    blocked = any(dec.action == Action.BLOCK for dec in decisions)
    rerouted = any(dec.action == Action.ROUTE for dec in decisions)
    allowed = not blocked and not rerouted

    audit_record = {
        "request_id": request_id,
        "timestamp": now.isoformat(),
        "actor_chain": chain,
        "chain_verified": chain_verified,
        "chain_reason": chain_reason,
        "intent": req.actor_chain[-1].intent if req.actor_chain else None,
        "destination": req.destination,
        "destination_approved": APPROVED_TOOLS.get(req.destination, {}).get("approved", False),
        "data_classes": sorted({d.data_class.value for d in detections}),
        "actions": [dec.action.value for dec in decisions],
        "allowed": allowed,
        "tokens_redacted": list(vault.keys()),
        "est_tokens": est_tokens,
        "est_cost_usd": est_cost,
        "cost_center": req.cost_center,
        "control": "ai-prompt-governance",
        "evidence_for": ["SOC2-CC6.1", "AI-Acceptable-Use", "Data-Protection"],
    }

    return GovernanceResult(
        mode="good", request_id=request_id, allowed=allowed,
        detections=detections, decisions=decisions,
        sanitized_prompt=sanitized, token_vault=vault,
        audit_record=audit_record, est_tokens=est_tokens, est_cost_usd=est_cost,
        chain_verified=chain_verified,
    )


# A canonical risky prompt used across the demo and the dashboard.
SAMPLE_RISKY_PROMPT = (
    "Debug this production error.\n"
    "User: Jane Smith\n"
    "Card: 4111 1111 1111 1111\n"
    "Account: ACME-48217\n"
    "Internal note: customer flagged for manual fraud review\n"
    "Traceback (most recent call last):\n"
    '  File "delivery.py", line 88, in send\n'
    "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
)


def sample_request(destination: str = "chatgpt-consumer") -> AIRequest:
    hops = [
        ("alice.dev", "human", "debug a failed delivery"),
        ("delivery", "delivery-agent", "diagnose delivery failure"),
        ("retrieval", "retrieval-agent", "fetch the matching record"),
    ]
    return AIRequest(
        prompt=SAMPLE_RISKY_PROMPT,
        actor_chain=[AgentHop(*h) for h in hops],
        destination=destination,
        cost_center="eng-platform",
        chain_tokens=identity.mint_chain(hops),
    )
