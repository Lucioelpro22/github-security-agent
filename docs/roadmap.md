# Roadmap

Directional only; items are not promises and may change after security and usability review.

## v0.1 — Read-only foundation

- [x] Define read-only boundary and advisory language.
- [x] Document architecture, threat model, safe use, and reporting.
- [ ] Add deterministic collectors for Actions, Dependabot, CodeQL, and repository hygiene.
- [ ] Add synthetic provider fixtures and unit tests.
- [ ] Add JSON schema and Markdown report rendering.
- [ ] Add CI for tests, linting, dependency audit, and secret scanning.

## v0.2 — Evidence quality

- [ ] Explicit collector coverage and unknown states.
- [ ] Pagination, timeout, retry, and rate-limit tests.
- [ ] Stable finding IDs and evidence references.
- [ ] SARIF export after redaction/schema validation.
- [ ] Public fixtures without credentials or private data.

## v0.3 — Operations

- [ ] Repository allow-lists and run budgets.
- [ ] Secure report retention and artifact handling.
- [ ] Tamper-evident run metadata and reproducible fixtures.
- [ ] Least-privilege GitHub App deployment guidance.
- [ ] Failure-injection and performance tests.

Future remediation proposals require separate design, explicit approval, previewed diffs, and an audit trail. Automatic writes, merges, secret retrieval, and bypasses remain out of scope.
