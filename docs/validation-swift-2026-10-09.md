# Swift real-lockfile validation — 2026-10-09

Validated the reader integrated at `5603720d9899a1520ad8487fa99060e127b7de47`
against three pinned public files from two repositories. Only selected lockfiles
were copied into isolated directories; no Swift, SwiftPM, Xcode, manifests,
scripts or project code was executed. No full project coverage is claimed.

| Repository and source file | Schema | Declared pins | Inventoried releases | Status |
| --- | --- | ---: | ---: | --- |
| swiftlang/swift-embedded-examples: root Package.resolved | 3 | 2 | 2 | complete |
| swiftlang/swift-embedded-examples: stm32-neopixel/Package.resolved | 3 | 3 | 2 | incomplete |
| pointfreeco/swift-composable-architecture: Integration Xcode Package.resolved | 2 | 12 | 12 | complete |

The embedded samples are fixed at
`119b29f83550efb39546e2359ad8368d5e6b6fd2`; the Xcode sample is fixed at
`bc2db5ba8ad3a47deba5db32fa340637ba6c9a76`. Full source paths, immutable
links, byte counts, SHA256 digests and observed identity/version pairs are in
[the validation data](validation-swift-2026-10-09.json).

Expected release pairs were read directly from each JSON pin's identity and
state.version and compared as a set with the parser output. There were no
missing or extra release pairs. The stm32-neopixel file's swift-mmio branch
pin has no release version: it was omitted, and the report correctly remained
incomplete while preserving swift-argument-parser and swift-syntax.

Every output package retained unknown origin. Both default and explicit
query-osv audit modes were exercised with the OSV transport mocked to raise
if called. No call occurred; explicit advisory lookup was incomplete for all
three samples because Swift packages are excluded from OSV.

These results demonstrate selected recorded-release inventory behavior, not
dependency resolution, manifest coverage, mirror configuration, revision/hash
verification, installed graphs or absence of vulnerabilities. See
[Swift compatibility and limits](swift-resolved.md).
