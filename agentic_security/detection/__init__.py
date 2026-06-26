"""Detection and response, as code.

    autoresponse  GuardDuty finding -> an automated response plan

The logic is what an EventBridge rule + Lambda would run. It returns the plan
(disable key, isolate instance, open incident, ...) rather than calling AWS, so it
is deterministic and testable; the Lambda is a thin boto3 shim over this.
"""
