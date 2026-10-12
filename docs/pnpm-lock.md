# pnpm lockfile inventory

The scanner supports lockfile formats `6.0` (pnpm v8) and `9.0`. It reads YAML
as untrusted data and never executes pnpm, Node, lifecycle scripts, package
manifests or workspace configuration. Formats 5.x, 6.1 and other versions are
not supported. Coverage follows the lockfile format, not the installed pnpm CLI.

## Format 6.0

Supports dedicated locks with dependency declarations at the root, shared
workspace `importers`, and slash-prefixed registry locators in `packages`.
Package snapshots and direct/transitive/optional references are inline.
Aliases use the resolved package identity, including `/name@version` references.
Package versions must be exact three-part SemVer, optionally with prerelease
and build metadata. Nested peer suffixes are preserved and bounded.

Every full snapshot locator is retained for graph validation. A reference must
match that exact locator, including its peer context; another context with the
same name/version cannot substitute for it. All snapshot variants are checked
independently of name/version inventory deduplication. These checks also apply to 9.0.
Different origins for the same name/version degrade the inventory origin to
unknown. Uninstallable optional snapshots remain inventoried.

Empty generated locks may omit `packages`. Explicit malformed importer values,
root/shared layout ambiguity, missing references, non-exact versions and
unsupported Git, file or absolute registry locators leave the scan incomplete.
Link/workspace references are recognized as external local references: they are
not opened or resolved, and no npm release record is fabricated for them.
Peer constraints, platform selection, bundled packages, manifest freshness and
workspace configuration are not resolved. A `package.json` without a supported
companion lock in the same directory remains incomplete under the local scanner's
manifest-coverage policy; a root workspace lock does not infer member coverage.

## YAML, bounds and network policy

One or two mapping documents are accepted under the existing document policy.
Each document must independently use a supported layout; graphs are not merged
across documents. Duplicate keys, anchors, aliases, unsafe tags, excessive
nesting and configured event, time, byte and dependency limits produce
incompleteness. Parsing errors contribute no packages from that lockfile;
bounded partial inventory can be retained with incomplete status.

OSV remains opt-in. A package is eligible only when its resolution tarball uses
HTTPS on the exact public host `registry.npmjs.org` under the existing URL gate.
Integrity-only metadata does not establish the registry, so it stays unknown and
excluded. Alternative hosts, credentials and ambiguous origins are excluded.
Even a public registry host can serve private package names. No URLs, integrity
values, scripts or lockfile text are sent to OSV; eligible name/version pairs
are sent only after explicit opt-in. An excluded inventory makes advisory lookup
incomplete when requested. Integrity hashes are not verified.

## References and selected validation

Format code and fixtures were checked against pnpm
[`afe8ecef1f24812845b699c141d52643d1524079`](https://github.com/pnpm/pnpm/tree/afe8ecef1f24812845b699c141d52643d1524079)
(v8.15.9), including `lockfile/lockfile-file/src/write.ts`,
`packages/dependency-path/src/index.ts`, and dedicated/workspace alias/peer
fixtures. The supplementary specification is pinned at
[`834f2815cc61917fa133e10869a2d4e9391c36bf`](https://github.com/pnpm/spec/blob/834f2815cc61917fa133e10869a2d4e9391c36bf/lockfile/6.0.md).
Its historical prose is not treated as authoritative over the actual v8 fixtures.

Independent YAML name/version extraction matched the scanner's inventory in
these three selected files. No project code ran and no OSV requests were made.
All selected package origins were unknown (integrity-only resolutions); explicit
OSV opt-in was tested with a transport guard and returned incomplete lookup.

| Repository and pinned commit | File | Package snapshots / unique pairs | SHA-256 |
| --- | --- | --- | --- |
| firecrawl/data-connectors `db990dba7946a85f70c7b05fc799fccbb81c3284` | `pnpm-lock.yaml` | 831 / 831 | `5610299840e75d3def2e2baf809e065a592ac390d1376fed98780d967f0420fb` |
| unjs/website `fe51311e828fe1a2ce6ecc8ebffa72f7190d44f8` | `pnpm-lock.yaml` | 1433 / 1433 | `0604e0acd5857910cb7e02764e77d57f771d71f8a4aca662de32999eeed4b936` |
| pnpm/pnpm `afe8ecef1f24812845b699c141d52643d1524079` | `__fixtures__/workspace-with-2-pkgs/pnpm-lock.yaml` | 1 / 1 | `c4b75183548c1903a2520a5fbc45b71190ae690994488d241b4bd836925f5001` |

Complete inventory for selected files does not demonstrate a complete installed
graph, archive integrity, or absence of vulnerabilities in those projects.
