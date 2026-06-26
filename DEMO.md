# Demo walkthrough

One command runs every domain, each contrasting a **BAD** state (tools, no
control) with a **GOOD** state (the control firing):

```bash
python3 demo.py
```

No install, no network, no API keys. Synthetic data only.

---

## 1 · AI prompt/data governance

A developer pastes a production error into an AI tool. It contains a payment card,
an account id, an internal note, a stack trace, and an AWS secret.

**BAD:** the prompt is forwarded raw to a consumer endpoint. No classification, no
identity, no audit, spend unattributed.

**GOOD:** the guardrail classifies each data class, decides a policy action, blocks
the secret, tokenizes the sensitive fields, reroutes off the unapproved tool,
verifies the agent identity, and emits one audit record:

```
GOOD  | detected: secret(high), pii(high), sensitive(medium), customer(medium), prod_log(medium)
GOOD  | decision BLOCK  - Secret detected; request blocked at the boundary
GOOD  | decision TICKET - Open secret-rotation ticket; secret is now considered exposed
GOOD  | decision REDACT - Tokenize pii into a non-identifiable unit
GOOD  | decision ROUTE  - Destination 'chatgpt-consumer' is not an approved AI tool
GOOD  | decision LOG    - Write AI-usage / SOC 2 evidence record

GOOD  | sanitized prompt that would leave the boundary:
       | Card: tok_pii_6160095f
       | tok_customer_555934c0: ACME-48217
       | tok_sensitive_26c1b0a9: customer flagged for manual fraud review
       | [BLOCKED:secret]

GOOD  | actor chain: human:alice.dev -> delivery-agent:delivery -> retrieval-agent:retrieval
GOOD  | chain verified: True (all hops verified)
GOOD  | one audit record emitted -> SOC2-CC6.1, AI-Acceptable-Use, Data-Protection
```

The raw card and secret never leave the boundary; the vault can re-identify the
tokens for an authorized downstream system. The same guardrail protects PHI in
healthcare or PII under GDPR/CCPA: only the data tier changes.

---

## 2 · AWS cloud finding triage

A few hundred synthetic AWS Security Hub findings. Sorting by severity puts noisy
"critical" labels on top and buries the dangerous ones. Sorting by **toxic
combination** surfaces the few that form a real attack path, each with an owner:

```
BAD   | top of the queue when you sort by vendor severity only:
       | critical FIND-1014  S3 bucket public (Block Public Access off)
       | critical FIND-1018  Security group open to 0.0.0.0/0 on 22/3389

GOOD  | top of the queue when you sort by risk (toxic combinations first):
       | score 140 [ATTACK-PATH] FIND-1000  owner=unassigned
       |            factors: internet_facing, sensitive_data, exploitable_high, privileged_iam, ...
```

> "I would not treat a few hundred findings as a few hundred equal problems."

---

## 3 · Security incident (AWS-native)

GuardDuty flags use of a leaked IAM access key, declared as a structured incident
with severity, roles, a timestamped containment timeline, and postmortem actions.
Every step names the evidence it produces:

```
GOOD  | INC-xxxxxx  [Sev2] GuardDuty flags use of a leaked IAM access key
       | Disabled the exposed IAM access key; attached a deny-all policy   evidence: IAM change + CloudTrail event
       | Isolated the affected EC2 with a quarantine security group        evidence: security-group change + CloudTrail
       | Rotated the key and reachable Secrets Manager secrets             evidence: Secrets Manager rotation record
       | Hunted persistence in CloudTrail (new IAM users/keys, AssumeRole) evidence: CloudTrail + GuardDuty query
```

> "The incident record becomes the operating evidence."

---

## 4 · SOC 2 evidence map (AWS-native)

Each control mapped to an owner, the AWS service that already emits its evidence,
and that evidence: continuous, not screenshot-at-audit-time:

```
| CC6.1   Encryption at rest   KMS + S3/EBS/RDS                      AWS Config rule: encryption-enabled
| CC7.2   Threat detection     GuardDuty + CloudTrail                GuardDuty findings + response
| CC6.2   Access reviews       IAM Identity Center + Access Analyzer Quarterly access-review attestation
```

> "SOC 2 is not paperwork. It is proof that the control operated."

---

## 5 · Secret + SAST scan of the local lab app

The scanner runs against the demo's **own** code, never any external target. The
deliberately insecure `app_bad.py` lights up; the hardened `app_good.py` is clean:

```
BAD   | lab/app_bad.py: 10 findings (high=8 med=1 low=1)
       |   [HIGH] hardcoded-aws-key, sql-string-concat, unauthenticated-endpoint x6
       |   [MED ] flask-debug-true
GOOD  | lab/app_good.py: 0 findings
```

The same scan runs in [CI](.github/workflows/security.yml). The test suite asserts
the bad app is caught and the good app is clean, so CI stays green while proving
the control fires before merge.

---

## 6 · TCPA outbound-message consent

Customer SMS sends are gated on consent. The same campaign, sent to six contacts,
is checked against prior express consent, the opt-out (STOP) list, and each
recipient's local 8am to 9pm window:

```
BAD   | blast every contact, no consent check, no opt-out, no quiet-hours ($500 to $1,500/msg)
ALLOW | A. Rivera    [opted_in ] America/New_York     within local calling window
BLOCK | C. Lindgren  [opted_in ] America/Los_Angeles  outside 8am to 9pm (06:00 local)
BLOCK | D. Patel     [opted_out] America/New_York     sent STOP, contact prohibited
GOOD  | 3/6 cleared; the rest stopped before they sent, each with a TCPA evidence record
```

The same control covers email under CAN-SPAM and GDPR/CCPA: swap "SMS send" for
"any outbound message".

---

**One pattern across every domain:** classify the risk -> assign an owner ->
enforce a control -> produce evidence -> escalate the exception.
