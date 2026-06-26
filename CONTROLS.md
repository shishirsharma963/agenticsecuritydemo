# Controls map

Every control in this repo mapped to its **NIST CSF 2.0** function and its
**SOC 2** Trust Services Criteria, with why it earns its place. One operating
pattern underneath all of them: classify the risk, assign an owner, enforce a
control, produce the evidence, escalate the exception.

CSF functions: **GV** Govern · **ID** Identify · **PR** Protect · **DE** Detect ·
**RS** Respond · **RC** Recover.

| Control (module) | NIST CSF | SOC 2 (TSC) | Why it matters |
|---|---|---|---|
| **threatmodel** (`threatmodel.py`) | ID.RA, GV.RM | CC3.1, CC3.2 | You can't protect what you haven't enumerated. STRIDE threats each map to a control that exists (tested), so the model can't drift into paper. |
| **baseline** (`cloud/baseline.py`) | PR.PS, DE.CM | CC6.1, CC6.6, CC7.1 | Prevention beats detection. SCPs make the insecure action impossible org-wide; Config rules catch drift. Rendered to real IaC. |
| **governance** (`governance.py`) | PR.DS, GV.OC | CC6.1, CC6.7, CC6.3 | Stops secrets and regulated data leaving through AI tools; routes regulated data only to DPA-covered endpoints; attributes spend. |
| **identity** (`identity.py`) | PR.AA | CC6.1, CC6.2 | Proves which human, through which agents, acted. Per-hop signed tokens; a forged or expired chain is blocked (non-repudiation). |
| **consent** (`consent.py`) | GV.OC, PR.DS | CC6.3 + Privacy (P) | Per-message TCPA liability. Consent + opt-out + quiet-hours before any outbound message; tokenized contact id in evidence. |
| **triage** (`triage.py`) | ID.RA, DE.CM | CC7.1 | A few hundred findings are not equal. Toxic-combination scoring surfaces real attack paths and routes each to an owner. |
| **scanner / SAST** (`scanner.py`) | PR.PS, DE.CM | CC8.1 | Catches secrets, SQLi, unauth endpoints, debug mode before merge. Gated in CI; the test suite proves it fires. |
| **dast** (`appsec/dast.py`) | DE.CM, PR.PS | CC8.1, CC7.1 | The dynamic half: runtime checks for auth, security headers, and error/stack-trace leakage. Hardened target must be clean to pass CI. |
| **autoresponse** (`detection/autoresponse.py`) | RS.MI, DE.AE | CC7.4 | Contains a leaked IAM key in seconds (disable, isolate). Destructive actions are severity-gated so a novel signal never causes an outage. |
| **incident** (`incident.py`) | RS.MA, RS.CO, RC.RP | CC7.3, CC7.4, CC7.5 | Structured response with roles and a timestamped timeline. The record *is* the audit evidence and feeds breach-notification timelines. |
| **soc2** (`soc2.py`) | GV.OV, DE.CM | CC4.1 (+ all via mapping) | Each control mapped to the AWS service that already emits its evidence, so the proof is continuous rather than an audit-time screenshot hunt. |

## Coverage at a glance

| CSF function | Covered by |
|---|---|
| **Govern (GV)** | threatmodel, governance, consent, soc2 |
| **Identify (ID)** | threatmodel, triage |
| **Protect (PR)** | baseline, governance, identity, consent, scanner, dast |
| **Detect (DE)** | baseline, triage, scanner, dast, autoresponse, soc2 |
| **Respond (RS)** | autoresponse, incident |
| **Recover (RC)** | incident (partial) |

## Honest gaps

- **Recover is thin.** Incident captures containment + postmortem, but backup/DR,
  restore testing, and resilience (RC.RP/RC.CO) are not modeled. In production this
  is AWS Backup + tested restores + an RTO/RPO target. Called out so the map shows
  real coverage, not a green wall.
- Several Protect/Detect controls are prototype-depth (regex DLP, line-regex SAST);
  see the README "Status and limitations" for the production path on each.
