# Passive repository scanner MVP

## Product goal

Extend GitHub Security Agent with an opt-in, read-only scan of repository files. The scanner reports actionable security risks before deployment; it does not edit files, open remediation commits, dismiss alerts, or block CI by default.

## MVP inputs and outputs

- Input: a checked-out repository tree and a versioned scanner configuration.
- Output: a deterministic JSON report and a readable Markdown summary.
- Every finding includes a stable rule ID, severity, confidence, file and line where available, redacted evidence, rationale, and a remediation recommendation.
- Reports distinguish a completed scan with no findings from an incomplete scan or scanner error.

## Initial detectors

1. GitHub Actions workflow risks: overly broad token permissions, unsafe pull request triggers, unpinned third-party actions, and direct interpolation of untrusted event fields into `run` commands. These checks are text heuristics, not a full YAML parser.
2. Repository configuration risks: common insecure settings and accidentally committed environment or credential files.
3. Secret patterns: local pattern-based detection with redaction; never copy detected values into logs or reports.
4. Dependency vulnerabilities: integrate a maintained advisory scanner as an optional detector after the core report contract is stable.

The scanner parses repository files as untrusted data. It must not run project scripts, install target dependencies, execute build hooks, or invoke package managers on the scanned project.

## Security defaults

- No GitHub token is required for local scanning.
- GitHub Actions runs with `contents: read`; no write permission is needed for Markdown/JSON artifacts.
- Do not use privileged pull request triggers to check out untrusted code.
- Pin third-party Actions to full commit SHAs.
- Bound file size, scan time, and report size; handle malformed input safely.
- Escape untrusted values in Markdown and workflow annotations.
- Exclusions must be explicit, narrow, documented, and visible in the report.
- Findings are advisory; users choose whether severity thresholds should fail CI.

## Out of scope for MVP

Automatic fixes, merging, alert dismissal, secret rotation, organization-wide dashboard, cloud-hosted repository uploads, and mandatory CI gates.

## Acceptance criteria

- Scanning a local fixture tree makes no network calls and executes no repository content.
- Identical inputs produce stable JSON output.
- Secret-like test values never appear in stdout, Markdown, or JSON.
- Tests cover positive, negative, malformed, oversized, and excluded fixtures for each detector.
- CI integration is optional and read-only, with artifact retention documented.
- Documentation explains false positives, scan limitations, and how to report a detector issue.
