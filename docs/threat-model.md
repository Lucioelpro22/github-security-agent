# Threat Model

## Scope

This covers authentication, GitHub API collection, parsing, finding generation, report storage, and operator review for the read-only workflow. It does not replace GitHub security features, penetration testing, incident response, or legal review.

## Assets and boundaries

Assets include credentials, private repository metadata, report integrity, API quota, and operator trust. Boundaries are: operator to agent; agent to GitHub API; provider response to parser; agent to report storage; report to operator.

## Threats and controls

| Threat | Impact | Control |
|---|---|---|
| Token leakage | Credential compromise | Least privilege, redaction, no secret echo |
| Scope expansion | Unauthorized private-data access | Explicit allow-list; fail closed; record scope |
| Prompt/content injection | Unsafe recommendations or execution | Treat fetched content as data; never execute it |
| Oversized/malicious response | Resource exhaustion | Limits, pagination, timeouts, bounded parsing |
| Missing permissions | False sense of security | Report unknown/unavailable, not pass |
| False positive remediation | Availability/integrity loss | Advisory output and human approval |
| Report tampering | Incorrect decisions | Stable schema, run metadata, controlled storage |
| Cross-repository mixing | Confidentiality/integrity loss | Validate repository identity; isolate runs |
| Supply-chain compromise | Code execution | Pin/review dependencies and CI actions |

## Requirements

Credentials come from a secret store. The default mode is read-only and exposes no write capability. Reports state repository, ref, collection time, collector coverage, and tool version. Sensitive reports follow an explicit retention policy.

Residual risks include provider changes, unavailable APIs, incomplete coverage, parser defects, and misclassification. Verify important findings against the repository and current provider documentation.
