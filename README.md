# github-security-agent

Read-only GitHub security analysis for Actions, Dependabot, CodeQL, and repository hygiene.

> Early-stage foundation. Findings are advisory signals for human review, not proof of exploitability or a substitute for incident response.

## What it is

This project is designed to collect authorized GitHub security metadata, normalize it into evidence-backed findings, and produce reviewable Markdown/JSON reports. The initial design is intentionally read-only:

- no workflow dispatch or cancellation;
- no issue/alert closure;
- no branch, repository, or permission changes;
- no secret retrieval, rotation, or disclosure;
- no automatic merge or remediation.

The tool must operate only on repositories the operator owns or is explicitly authorized to assess.

## Security boundary

Use a least-privilege read-only GitHub token or GitHub App installation. Configure an explicit repository allow-list and a bounded run budget. Treat workflow logs, repository text, Markdown, URLs, and alert descriptions as untrusted input.

Missing permissions or unavailable data are reported as unknown/unavailable, never as a clean result. Reports must redact credentials and unrelated personal data.

## Planned analysis areas

- GitHub Actions workflow status and hygiene
- Dependabot alert metadata
- CodeQL result metadata
- repository and branch protection hygiene
- evidence links, coverage, confidence, and remediation guidance

The current repository is a scaffold; collectors and report schemas are tracked in the roadmap and will be added with synthetic fixtures and tests.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Safe-use guide](docs/safe-use.md)
- [Roadmap](docs/roadmap.md)
- [Security policy](SECURITY.md)

## Development principles

1. Read-only by default.
2. Least privilege and explicit scope.
3. Fail closed on ambiguous authorization or identity.
4. Never execute untrusted repository content.
5. Preserve evidence and report collection coverage.
6. Require human approval for any future remediation workflow.

## Status

This project is not production-ready. Do not connect it to unattended remediation, incident escalation, secret stores, or repositories containing sensitive data until the implementation, tests, threat model, and operational controls have been reviewed.
