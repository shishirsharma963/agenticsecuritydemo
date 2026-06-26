"""Cloud security baseline: preventive guardrails as IaC.

    baseline  Service Control Policies + AWS Config rules, rendered to a real SCP
              policy document and Terraform, plus a compliance check against a
              mock account state (the preventive -> detective loop).

Stdlib + synthetic. AWS-native, domain-neutral.
"""
