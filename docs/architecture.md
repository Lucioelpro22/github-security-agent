# Architecture

The agent separates target validation, read-only collection, normalized findings, and deterministic reporting. Provider implementations must not mutate repositories. Remediation remains a human-approved future capability.

## Safety invariants

- Read-only and dry-run by default.
- Remote collection is opt-in; the default provider remains offline and empty.
- The GitHub provider uses fixed HTTPS GET endpoints for Dependabot, Code Scanning, and Secret Scanning alerts.
- API failures and configured limits fail the inventory instead of appearing as zero findings.
- No secrets or full repository contents in findings.
- Secret scanning requests use \`hide_secret=true\`; reports retain only the alert type.
- Remote titles are untrusted input and are escaped for Markdown output.
- Offline tests never require GitHub credentials.
- Unknown data is reported as unknown, never as safe.
