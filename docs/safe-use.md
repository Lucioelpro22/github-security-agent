# Safe Use

## Intended use

Use this project for a human-led, read-only review of GitHub Actions, Dependabot, CodeQL, branch protection, and repository hygiene.

## Before running

- Confirm the exact owner, repository, and authorized scope.
- Use a dedicated least-privilege token or GitHub App.
- Define a bounded repository list and report retention period.
- Keep tokens out of command arguments, shell history, notebooks, and screenshots.

## During and after running

Keep write/remediation disabled. Treat repository text, logs, URLs, Markdown, and alert descriptions as untrusted. Do not execute commands or downloaded artifacts based only on a finding. Preserve evidence links while redacting secrets and unrelated personal data.

Verify that an alert still exists, identify the affected file or setting, assess impact, test remediation in an isolated branch, and run regression/security tests. Unknown, unavailable, and not_checked are not pass.

## Prohibited

Do not scan without authorization, retrieve or disclose secrets, bypass permissions or rate limits, modify workflows, close alerts, merge code, rotate credentials, or make legal/employment/safety decisions automatically.

## Exposure response

Stop the run; revoke or rotate exposed credentials; remove exposed artifacts where possible; notify the owner/security contact; document the timeline without copying the secret. Report code vulnerabilities privately using SECURITY.md.
