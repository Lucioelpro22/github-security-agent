# Roadmap

1. Stabilize offline domain objects and deterministic report contracts.
2. Implement local, read-only repository scanning with fixture-based tests; parse files as untrusted data and never execute repository code.
3. Add first detectors for GitHub Actions workflow risks, unsafe repository configuration, and redacted secret-pattern matches.
4. Add optional dependency advisory scanning and JSON/Markdown output with confidence, evidence, exclusions, and scan status. (Implemented for pinned requirements, npm, Yarn, pnpm v9, Poetry, Cargo, uv, Go, and Composer lockfiles; OSV.dev queries remain opt-in and source-aware. Composer inventories production/development packages locally; its registry origin cannot be proven from download URLs, so OSV queries are excluded. Additional ecosystems remain future work.)
5. Package an opt-in GitHub Action with least-privilege permissions and downloadable reports; keep CI non-blocking by default. (Implemented as a read-only composite Action. It uploads only Markdown/JSON reports and fails on incomplete scans only when explicitly configured.)
6. Add a read-only GitHub API provider after the local scanner is stable and independently reviewed. (Implemented as an opt-in provider for alert inventories with documented read-only permissions, bounded pagination, explicit incomplete failures, and secret-safe normalization.) The API coverage and token handling were validated before implementing a static, offline JSON viewer. The viewer now consumes versioned GitHub alert, local scan, and dependency audit reports while preserving each source's status and severity semantics.

Automatic fixes, merges, alert dismissal, and secret rotation remain out of scope. Any future write capability requires explicit human approval and a separate security review.
