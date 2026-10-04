# Architecture

The agent separates target validation, read-only collection, normalized findings, and deterministic reporting. Provider implementations must not mutate repositories. Remediation remains a human-approved future capability.

## Safety invariants

- Read-only and dry-run by default.
- No secrets or full repository contents in findings.
- Offline tests never require GitHub credentials.
- Unknown data is reported as unknown, never as safe.
