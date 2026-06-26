# Design decisions (ADR log)

Short record of the choices behind Agentic Security Demo and why. This is a prototype to
demonstrate an operating model; decisions favor clarity and runnability over
production completeness. See the README "Limitations & V2 roadmap" for the
matching production paths.

## 1. Synthetic data, real mechanisms
Decision: mock all data (PII / customer records, a few hundred findings) but keep
the mechanisms real (Luhn check, classifiers, tokenization, risk scoring, scanner).
Why: to show how I approach controls, runnable in one command, without touching
any real environment.

## 2. One logic core, two thin presenters
Decision: all logic in `agentic_security/`; `demo.py` (CLI) and `dashboard/` (Streamlit)
are dumb views over it; tests exercise the same core.
Why: lets "the mechanism is real, the data is mocked" actually be true, one code
path runs in the CLI, the UI, and CI.

## 3. Regex + Luhn classifiers (a stub, on purpose)
Decision: deterministic regex for secrets/PII + a real Luhn check (payment cards).
Why: cheap, inspectable, zero-dependency. Known limitation: false positives /
negatives. V2 = a DLP engine or a commercial DLP with context models.

## 4. Tokenization as a placeholder
Decision: truncated SHA-256 into an in-memory vault.
Why: enough to show "raw value never leaves the boundary." Not secure (collisions,
plaintext vault). V2 = envelope encryption via a key-management service + format-preserving tokenization.

## 5. Additive risk scoring vs. graph attack-paths
Decision: additive weights (reachability × value × exploitability), with a few
attack paths seeded so the demo always has criticals.
Why: the weighting model is the defensible artifact and it's tunable. Real tools
(modern CNAPP tools) do graph reachability + EPSS / data-sensitivity; noted as V2.

## 6. Agent identity: strings first, then verifiable
Decision: started with an illustrative `actor_chain`; upgraded to per-hop signed
tokens (HMAC, stdlib).
Why: be honest that the first cut wasn't verifiable, then close the gap. The
production-grade version (an STS minting RS256 JWTs) is the sibling
[agentidentity](https://github.com/shishirsharma963/agentidentity) repo.

## 7. Self-scanning lab, gated in CI
Decision: ship a deliberately-vulnerable `lab/app_bad.py` + hardened `app_good.py`;
the scanner runs against them and the test suite asserts the result.
Why: the control proves itself in CI (bad caught, good clean) while staying green.
Limitation: SAST-lite (line regex), evadable, a stub for a SAST engine / a secret scanner.

## 8. No real LLM / network / cloud
Decision: in-process, no external calls.
Why: deterministic, safe to run, safe to share. The architecture is what scales.
