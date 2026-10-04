# Architecture

## Purpose

github-security-agent is a read-only GitHub security posture analyzer. It collects authorized metadata and produces reviewable reports. It does not modify repositories, merge pull requests, rotate secrets, or remediate automatically.

## Flow

\`\`\`mermaid
flowchart LR
  A[Authorized GitHub data] --> B[Collectors]
  B --> C[Normalized findings]
  C --> D[Policy rules]
  D --> E[Report and evidence]
  E --> F[Human review]
\`\`\`

## Components

- **Collectors:** Actions, Dependabot, CodeQL, repository and branch hygiene; only explicitly enabled sources.
- **Normalizer:** stable finding records with category, severity, confidence, evidence location, and guidance.
- **Policy engine:** deterministic rules; a finding is an observation, not proof of exploitability.
- **Report writer:** Markdown and JSON outputs with links and metadata, never secret values.
- **Review boundary:** a human validates scope, evidence, impact, and remediation.

## Data boundaries

Use the smallest read-only GitHub scope. Never request or print tokens, private keys, passwords, webhook secrets, or full secret values. Redact authorization headers, token-like strings, credential-bearing URLs, and unnecessary response bodies.

## Modes and failure behavior

The initial release is read-only: one-repository review, explicit organization allow-list review, or analysis of exported security artifacts. Fail closed on ambiguous identity, authorization, or scope. Distinguish not_found, forbidden, rate_limited, and provider_error; missing data is not a clean result. Bound pagination, response sizes, timeouts, and retries.

GitHub responses, workflow logs, Markdown, and repository text are untrusted input. Parsers must not execute content or dynamically evaluate it.
