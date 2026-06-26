# Threat model

STRIDE threat model for the AI/agent platform this repo protects. It is kept as
data in [`agentic_security/threatmodel.py`](agentic_security/threatmodel.py) so a
test can assert every threat maps to a control that actually exists; this file is
the narrative.

## System and data flow

```
   human ──▶ delivery-agent ──▶ retrieval-agent ──▶ AI model (Anthropic/OpenAI/Bedrock)
     │             │                    │                 ▲
     └── signed ───┴──── signed ────────┘                 │
         per-hop identity (identity.py)         governance guardrail (governance.py)
                                                classify · tokenize · route · audit
                                                          │
   AWS account: IAM, S3, EC2, RDS, Lambda, KMS ──────────┘
     observed by GuardDuty / Security Hub / CloudTrail / Config
       findings ─▶ triage ─▶ owners        events ─▶ auto-response ─▶ incident
```

Trust boundaries: (1) human → agent, (2) agent → agent, (3) platform → external
AI model, (4) workload → AWS control plane. The guardrail and the signed identity
chain sit on boundaries 1–3; AWS-native detection covers boundary 4.

## STRIDE summary

| Threat | STRIDE | Component | Mitigation | Control | Status |
|---|---|---|---|---|---|
| T01 | Spoofing | agent chain | per-hop signed tokens, verified at the gateway | identity | mitigated |
| T02 | Tampering | AI guardrail | input classification + scoped tools (output review V2) | governance | partial |
| T03 | Info disclosure | AI guardrail | DLP + secret block + tokenization + DPA routing | governance | mitigated |
| T04 | Info disclosure | AI tool egress | approved-tool registry, DPA-only for regulated data | governance | mitigated |
| T05 | Repudiation | audit | signed actor chain in one audit record | identity | mitigated |
| T06 | Elevation | AWS IAM | least privilege + Access Analyzer; attack-path triage | triage | partial |
| T07 | Spoofing | AWS IAM | GuardDuty → auto disable key + isolate | autoresponse | mitigated |
| T08 | Tampering | agent tools | per-hop intent + audience-scoped tokens | identity | partial |
| T09 | Info disclosure | AWS data stores | attack-path prioritization of exposed + sensitive | triage | partial |
| T10 | DoS | AI spend | per-request spend attribution; budget alerts V2 | governance | partial |
| T11 | Repudiation | compliance | continuous evidence mapped to AWS services | soc2 | mitigated |
| T12 | Tampering | SDLC | SAST + secret scan + DAST gated in CI | scanner | mitigated |
| T13 | Info disclosure | outbound messaging | consent + opt-out + quiet-hours check | consent | mitigated |
| T14 | Tampering | app surface | DAST: auth, headers, error/debug leakage | dast | mitigated |

## How to read it

- **OWASP LLM Top 10** and **MITRE ATLAS** references are in the data module's `ref`
  field. The AI-specific ones (T02, T03, T04, T08, T10) are the part most teams
  have not modeled yet.
- The honest gaps are the `partial` rows: those are the next investments
  (output-side prompt-injection defenses, IAM least-privilege automation, exposed
  data-store auto-remediation, spend budgets). `threatmodel.gaps()` returns them.

## Where this applies

The model is domain-neutral. In a regulated industry the "sensitive data" in T03
and T09 is the PHI/PCI/PII tier, and T13 maps to patient/customer outreach under
HIPAA/TCPA. The threats and controls do not change; only the data classification does.
