"""Agentic Security Demo: turning security tools into operating controls.

A synthetic-data prototype that shows the difference between a team that *bought*
security tools and one that turned them into controls that produce evidence.
Every domain shares one operating pattern:

    classify the risk -> assign an owner -> enforce a control
    -> produce evidence -> escalate the exception.

Modules:
    governance  AI prompt/data guardrail (classify, tokenize, route, audit)
    identity    per-hop signed agent identity (verifies the actor chain)
    consent     TCPA SMS-consent guardrail
    triage      AWS finding risk scoring via toxic combinations
    incident    structured incident lifecycle + evidence
    soc2        SOC 2 control -> owner -> AWS service -> evidence map
    scanner     secret + SAST static scanner for the local lab app

Everything here is mock data. It does not touch any real environment.
"""

__version__ = "0.1.0"
