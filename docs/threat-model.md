# Threat model

Assets include GitHub tokens, repository metadata, security findings, and generated reports. Main threats are credential leakage, over-privileged automation, untrusted repository content, denial of service, and false assurance from incomplete data.

## Mitigations

- The GitHub API provider is opt-in and accepts a token only through a named environment variable, never as a CLI argument.
- Documented fine-grained token permissions are read-only and scoped to one repository: Dependabot alerts, Code scanning alerts, and Secret scanning alerts.
- Only fixed GitHub.com alert-list endpoints and GET requests are implemented. No arbitrary API paths or write operations are exposed.
- The token is not copied into findings, reports, or error messages. Secret scanning requests set \`hide_secret=true\`, and the normalizer ignores any literal secret field.
- API responses are bounded to 2 MB; pagination is bounded to 10 pages per alert class, 100 results per page, and 10-second request timeouts.
- Pagination links are restricted to HTTPS \`api.github.com\` and the expected endpoint. Errors, denied permissions, unsupported alert features, and limits fail closed with an incomplete-scan exit status.
- Remote alert text is untrusted. Markdown output escapes HTML and Markdown syntax; the static report viewer inserts values only through `textContent` and never interprets HTML or Markdown.
- The dashboard viewer runs from a local static file, has no server, API token, persistence, or network access; it accepts only complete schema-version-1 JSON up to 5 MB and 3,000 findings, and drops fields outside its allowlist.
- Tests use mocked responses and do not require real credentials or network calls.
- Human approval remains required for any future write capability.
