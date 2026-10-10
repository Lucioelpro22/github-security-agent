# Dart/Flutter lock inventory

The scanner reads `pubspec.lock` as untrusted YAML. It never executes Dart,
Flutter, Pub, build hooks, or `pubspec.yaml`; it does not access package caches,
fetch repositories, open description paths, or resolve SDK constraints.

## Supported inventory

A single mapping document with a `packages` mapping is supported. Each package
must have a bounded identifier, exact three-component semantic version,
recognized source, and valid source description. Dependency classifications
`direct main`, `direct dev`, `direct overridden`, and `transitive` are accepted.

- Hosted: legacy description equal to the package name, or a mapping with
  matching `name`, `url`, and optional 64-hex `sha256`. Origin is `registry-other`
  even when the URL names pub.dev; URLs and hashes are not exported or verified.
- Git: bounded URL, resolved commit, optional ref, path and tag pattern. Origin
  is `git`; the recorded package version is not proof of a registry release.
- Path: bounded path and boolean `relative`. Origin is `directory`; paths are
  metadata and are never followed.
- SDK: bounded SDK description. Origin is `unknown`; SDK presence is not checked.

All Dart records are excluded from OSV, including when `--query-osv` is enabled.
In that case advisory lookup remains incomplete for excluded dependencies.
The report uses `Dart` as an inventory label, without asserting an OSV ecosystem.

## Incompleteness and limits

Malformed records, unsupported fields/sources, unsafe versions, duplicate YAML
keys, aliases/anchors, merge keys, custom tags, multiple documents, excessive
nesting, and configured file/byte/package/node limits leave the scan incomplete.
Valid records from a structurally readable file may be retained alongside
incomplete status. A structurally invalid YAML file contributes no packages.

`pubspec.yaml` requires a readable `pubspec.lock` in the same directory. A nested
lock does not cover a parent manifest. Workspace resolution and custom lock
locations are not inferred, so workspace members without local companion locks
remain incomplete. Empty package maps describe only the selected lockfile.

`complete` means the supported entries were inventoried; it does not establish
the installed dependency graph, manifest freshness, runtime compatibility,
archive integrity, or absence of vulnerabilities.

## Format reference

The format and source descriptions were checked against Dart Pub at commit
[`a9ed06f7fb180b39b950aec878d4aa0911b7675e`](https://github.com/dart-lang/pub/tree/a9ed06f7fb180b39b950aec878d4aa0911b7675e):
`lib/src/lock_file.dart` and `lib/src/source/{hosted,git,path,sdk}.dart`.
The scanner implements a bounded, conservative inventory subset of that code.

## Selected real-file validation

The `pubspec.lock` from the pinned Dart Pub commit above contains 58 packages.
An independent YAML read and this inventory were compared by package name and
version. This includes the leading-underscore `_fe_analyzer_shared` package.
The original file SHA-256 is
`91bb3ab716d11d22028ad6e6da48a3ca1c2d70114393edd35787615bd379527f`.
No project code was run and no advisory request was made. This validates only
that selected file, not the repository's complete runtime graph.
