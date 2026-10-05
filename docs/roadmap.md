# Roadmap

1. Stabilize offline domain objects and deterministic report contracts.
2. Implement local, read-only repository scanning with fixture-based tests; parse files as untrusted data and never execute repository code.
3. Add first detectors for GitHub Actions workflow risks, unsafe repository configuration, and redacted secret-pattern matches.
4. Add optional dependency advisory scanning and JSON/Markdown output with confidence, evidence, exclusions, and scan status. (Dependency inventory and opt-in OSV.dev queries are implemented for pinned requirements and npm, Poetry, and Cargo lockfiles; remaining ecosystem coverage is future work.)
5. Package an opt-in GitHub Action with least-privilege permissions and downloadable reports; keep CI non-blocking by default. (Implemented as a read-only composite Action. It uploads only Markdown/JSON reports and fails on incomplete scans only when explicitly configured.)
6. Consider a GitHub API provider and dashboard only after the local scanner is reliable and independently reviewed.

Automatic fixes, merges, alert dismissal, and secret rotation remain out of scope. Any future write capability requires explicit human approval and a separate security review.
