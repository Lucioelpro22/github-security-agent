# Swift Package.resolved inventory

The offline dependency auditor reads `Package.resolved` JSON schemas 2 and 3,
including files nested under Xcode project/workspace directories. It inventories
the declared identity and exact release version under the report label `Swift`.
That label is for local reports, not a claim of OSV ecosystem compatibility.
All source kinds remain `unknown`; Swift pins are never sent to OSV, including
when `--query-osv` is enabled. In that case advisory coverage is incomplete.

The scanner does not execute Swift, SwiftPM, Xcode or `Package.swift`, and never
opens locations from pins. It does not disclose source URLs, local locations,
`originalLocation`, branch names or `originHash` in reports. Package identities
and versions themselves can be private; handle downloaded reports accordingly.

Compatibility is a bounded subset of SwiftPM's storage model:

- Versions 2 and 3 only; version 1 and unknown versions report incompleteness.
- Source-control release pins accept an optional 40/64-digit hexadecimal
  revision. Registry pins accept an empty location and a release version,
  without a branch or revision. Locations remain untrusted opaque metadata.
- Branch/revision-only pins lack a release version; they are omitted and the
  report is incomplete. No Git revision is invented as a release version.
- Identities use bounded ASCII letters, digits, dots, underscores and hyphens;
  duplicates are compared without case. Suspicious token-shaped identities
  and versions are rejected.
- Simultaneous version/branch fields and registry version/revision fields are
  conservatively rejected, even though SwiftPM's general state decoder is more
  permissive. Unknown fields and malformed metadata report incompleteness.
- `originHash` is optional opaque metadata, not validated against a manifest
  or treated as integrity or provenance evidence.
- Existing byte, total-byte, file, package and elapsed scan limits apply.
  JSON duplicate keys and deep recursion fail closed at the scanner boundary.

`Package.swift` without `Package.resolved` in the same directory marks coverage
unknown. The scanner does not infer Xcode project-to-lock associations or custom
lock locations. A nested Xcode lock does not cover a separate Swift manifest.
It does not resolve dependency constraints, inspect roots/transitive edges,
verify Git revisions, checksums or mirrors, or prove which packages are installed.
An empty pin array is an empty recorded inventory, not evidence of a dependency-free build.

## Format sources

Implementation based on SwiftPM source at
`5546f44a3b524e2b57c05ba5185094aa8adc0bde`:

- [ResolvedPackagesStore.swift](https://github.com/swiftlang/swift-package-manager/blob/5546f44a3b524e2b57c05ba5185094aa8adc0bde/Sources/PackageGraph/ResolvedPackagesStore.swift)
- [PackageIdentity.swift](https://github.com/swiftlang/swift-package-manager/blob/5546f44a3b524e2b57c05ba5185094aa8adc0bde/Sources/PackageModel/PackageIdentity.swift)
- [Resolving package versions](https://github.com/swiftlang/swift-package-manager/blob/5546f44a3b524e2b57c05ba5185094aa8adc0bde/Sources/PackageManagerDocs/Documentation.docc/ResolvingPackageVersions.md)
