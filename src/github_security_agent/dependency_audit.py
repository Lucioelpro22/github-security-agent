"""Opt-in dependency inventory and OSV.dev advisory lookup.

The default audit is fully local. Network requests are made only when the caller
explicitly enables advisory lookup; only package names, ecosystems, and exact
versions are sent, never source files or lockfile contents.
"""

from __future__ import annotations

from .http_transport import urlopen_no_redirect

import html
import json
import os
import re
import stat
import tomllib
import yaml  # type: ignore[import-untyped]
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, ClassVar, cast

MAX_LOCKFILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 20_000_000
MAX_LOCKFILES = 100
MAX_DEPENDENCIES = 5_000
MAX_BATCH_SIZE = 100
MAX_OSV_BATCHES = 5
MAX_RESPONSE_BYTES = 2_000_000
MAX_SCAN_SECONDS = 30
OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
_PINNED = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)(?:\s*;.*)?$")
_SAFE_UNSCOPED_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_SAFE_SCOPED_NAME = re.compile(r"^@[A-Za-z0-9._-]{1,128}/[A-Za-z0-9._-]{1,128}$")
_SAFE_GO_MODULE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._!~+-]{0,255}(?:/[A-Za-z0-9._!~+-]{1,255})*$")
_SAFE_VERSION = re.compile(r"^v?\d[A-Za-z0-9.+!_-]{0,127}$")
_SENSITIVE_NAME = re.compile(
    r"(?i)^(?:gh[pousr]_|github_pat_|akia[0-9a-z]{16}\b|xox[baprs]-|sk-[a-z0-9_-]{20,})"
)
_SENSITIVE_VERSION_TOKEN = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Za-z0-9]{32,}(?![A-Za-z0-9])")
MAX_REQUEST_BYTES = 64_000
_MANIFEST_COMPANIONS = {
    "pyproject.toml": {
        "requirements.txt",
        "requirements-lock.txt",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
    },
    "package.json": {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
    "composer.json": {"composer.lock"},
    "Pipfile": {"Pipfile.lock"},
    "Cargo.toml": {"Cargo.lock"},
    "go.mod": {"go.sum"},
    "Gemfile": {"Gemfile.lock"},
    "Package.swift": {"Package.resolved"},
    "pubspec.yaml": {"pubspec.lock"},
    "pom.xml": set(),
    "build.gradle": {"gradle.lockfile"},
    "build.gradle.kts": {"gradle.lockfile"},
}


def _requirements_have_unresolved_entries(text: str) -> bool:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or _PINNED.fullmatch(line):
            continue
        if line.startswith(
            ("--index-url", "--extra-index-url", "--find-links", "-i ", "--trusted-host")
        ):
            continue
        return True
    return False


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str
    source_kind: str | None = None


@dataclass(frozen=True, slots=True)
class Advisory:
    dependency: Dependency
    advisory_id: str
    summary: str


@dataclass(frozen=True, slots=True)
class DependencyReport:
    status: str
    manifests_scanned: int
    dependencies: tuple[Dependency, ...]
    advisories: tuple[Advisory, ...]
    advisory_lookup: str
    errors: tuple[str, ...]


def _public_registry_url(value: str, host: str, paths: set[str]) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname == host
            and (not paths or parsed.path.rstrip("/") in paths)
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _poetry_source_kind(source: Any) -> str:
    if source is None:
        return "registry-pypi"
    if not isinstance(source, dict):
        return "unknown"
    source_type = source.get("type")
    if source_type == "legacy" and isinstance(source.get("url"), str):
        return (
            "registry-pypi"
            if _public_registry_url(source["url"], "pypi.org", {"/simple"})
            else "registry-other"
        )
    if source_type == "git":
        return "git"
    if source_type in {"directory", "file"}:
        return "directory"
    if source_type == "url":
        return "url"
    return "unknown"


def _cargo_source_kind(source: Any) -> str:
    if source is None:
        return "workspace"
    if not isinstance(source, str):
        return "unknown"
    if source.startswith("registry+"):
        registry = source.removeprefix("registry+")
        return (
            "registry-cratesio"
            if _public_registry_url(registry, "github.com", {"/rust-lang/crates.io-index"})
            or _public_registry_url(registry, "index.crates.io", {""})
            else "registry-other"
        )
    if source.startswith("sparse+"):
        registry = source.removeprefix("sparse+")
        return (
            "registry-cratesio"
            if _public_registry_url(registry, "index.crates.io", {""})
            else "registry-other"
        )
    if source.startswith("git+"):
        return "git"
    return "unknown"


def _npm_source_kind(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    return (
        "registry-npm"
        if _public_registry_url(value, "registry.npmjs.org", set())
        else "registry-other"
    )


def _parse_requirements(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    records: list[Dependency] = []
    lines = text.splitlines()
    alternate_index = any(
        line.split("#", 1)[0]
        .strip()
        .startswith(("--index-url", "--extra-index-url", "--find-links", "-i ", "--trusted-host"))
        for line in lines
    )
    for line in lines:
        line = line.split("#", 1)[0].strip()
        match = _PINNED.fullmatch(line)
        if match:
            if len(records) >= limit:
                return records, True
            records.append(
                Dependency(
                    match.group(1),
                    match.group(2),
                    "PyPI",
                    path,
                    "registry-other" if alternate_index else "registry-pypi",
                )
            )
    return records, False


def _walk_npm_dependencies(
    dependencies: Any, path: str, limit: int
) -> tuple[list[Dependency], bool]:
    records: list[Dependency] = []
    pending = [dependencies]
    while pending:
        current = pending.pop()
        if not isinstance(current, dict):
            continue
        for name, value in current.items():
            if not isinstance(name, str) or not isinstance(value, dict):
                continue
            version = value.get("version")
            if isinstance(version, str) and version:
                if len(records) >= limit:
                    return records, True
                records.append(
                    Dependency(name, version, "npm", path, _npm_source_kind(value.get("resolved")))
                )
            nested = value.get("dependencies")
            if isinstance(nested, dict):
                pending.append(nested)
    return records, False


def _yarn_scalar(value: str) -> str:
    value = value.strip()
    if value.startswith('"'):
        decoded = json.loads(value)
        if not isinstance(decoded, str):
            raise ValueError("invalid Yarn scalar")
        return decoded
    if value.startswith("'"):
        if not value.endswith("'"):
            raise ValueError("invalid Yarn scalar")
        return value[1:-1].replace("''", "'")
    return value


def _yarn_selectors(header: str) -> list[str]:
    selectors: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in header:
        if escaped:
            current.append(char)
            escaped = False
        elif quote == '"' and char == "\\":
            current.append(char)
            escaped = True
        elif quote is not None:
            current.append(char)
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            current.append(char)
            quote = char
        elif char == ",":
            selectors.append(_yarn_scalar("".join(current)))
            current = []
        else:
            current.append(char)
    if quote is not None or escaped:
        raise ValueError("invalid Yarn selector header")
    selectors.append(_yarn_scalar("".join(current)))
    return [selector.strip() for selector in selectors if selector.strip()]


def _yarn_selector_name(selector: str) -> tuple[str, bool]:
    if selector.startswith("@"):
        slash = selector.find("/")
        separator = selector.find("@", slash + 1) if slash >= 0 else -1
        if slash <= 1 or separator <= slash + 1:
            raise ValueError("invalid Yarn package selector")
        name = selector[:separator]
        selector_range = selector[separator + 1 :]
        aliased = False
    else:
        name, has_separator, selector_range = selector.partition("@")
        if not has_separator:
            raise ValueError("invalid Yarn package selector")
        aliased = selector_range.startswith("npm:")
        if aliased and not selector_range.removeprefix("npm:"):
            raise ValueError("invalid Yarn package selector")
    if not selector_range or not (
        _SAFE_SCOPED_NAME.fullmatch(name)
        if name.startswith("@")
        else _SAFE_UNSCOPED_NAME.fullmatch(name)
    ):
        raise ValueError("invalid Yarn package name")
    return name, aliased


def _yarn_source_kind(resolved: str | None, *, classic: bool, aliased: bool) -> str:
    if not classic or aliased or resolved is None:
        return "unknown"
    try:
        parsed = urlsplit(resolved)
    except ValueError:
        return "registry-other"
    if parsed.fragment and not re.fullmatch(r"[A-Fa-f0-9]{40}", parsed.fragment):
        return "registry-other"
    public_url = parsed._replace(fragment="").geturl()
    if _public_registry_url(public_url, "registry.npmjs.org", set()) or _public_registry_url(
        public_url, "registry.yarnpkg.com", set()
    ):
        return "registry-npm"
    return "registry-other"


def _parse_yarn_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    classic = "# yarn lockfile v1" in text.splitlines()[:10]
    records: list[Dependency] = []
    names: list[str] = []
    aliased = False
    version: str | None = None
    resolved: str | None = None

    def finish_entry() -> bool:
        nonlocal names, aliased, version, resolved
        if not names:
            return False
        if not version:
            raise ValueError("Yarn entry has no exact version")
        if len(records) >= limit:
            return True
        source_kind = _yarn_source_kind(resolved, classic=classic, aliased=aliased)
        records.append(Dependency(names[0], version, "npm", path, source_kind))
        names = []
        aliased = False
        version = None
        resolved = None
        return False

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 0:
            if finish_entry():
                return records, True
            if line == "__metadata:":
                continue
            if not line.endswith(":"):
                raise ValueError("unrecognized Yarn lockfile structure")
            selectors = _yarn_selectors(line[:-1])
            if not selectors:
                raise ValueError("empty Yarn selector")
            parsed_names = [_yarn_selector_name(selector) for selector in selectors]
            if len({name for name, _ in parsed_names}) != 1:
                raise ValueError("Yarn header combines different package names")
            names = [parsed_names[0][0]]
            aliased = any(is_alias for _, is_alias in parsed_names)
            continue
        if indent != 2 or not names:
            continue
        if line.startswith("version:"):
            version = _yarn_scalar(line.partition(":")[2])
        elif line.startswith("version "):
            version = _yarn_scalar(line[len("version ") :])
        elif line.startswith("resolved "):
            resolved = _yarn_scalar(line[len("resolved ") :])
        elif line.startswith("resolution:"):
            # Berry locators do not reveal the configured npm registry.
            resolved = None

    if finish_entry():
        return records, True
    if not records and not classic:
        raise ValueError("unsupported Yarn lockfile format")
    return records, False


MAX_PNPM_YAML_EVENTS = 100_000
MAX_PNPM_YAML_DEPTH = 64
MAX_PNPM_YAML_ALIASES = 64


class _StrictPnpmLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader with duplicate-key, depth, and node limits."""

    yaml_implicit_resolvers: ClassVar[dict[Any, Any]] = {}

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self.node_count = 0
        self.depth = 0
        self.alias_count = 0
        self.started_at = time.monotonic()

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            self.alias_count += 1
            if self.alias_count > MAX_PNPM_YAML_ALIASES:
                raise yaml.YAMLError("too many YAML aliases")
        self.depth += 1
        self.node_count += 1
        if self.depth > MAX_PNPM_YAML_DEPTH or self.node_count > MAX_PNPM_YAML_EVENTS:
            raise yaml.YAMLError("YAML resource limit exceeded")
        if time.monotonic() - self.started_at > MAX_SCAN_SECONDS:
            raise yaml.YAMLError("YAML parse time limit exceeded")
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.YAMLError("expected a YAML mapping")
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode) or key_node.value == "<<":
                raise yaml.YAMLError("unsupported YAML mapping key")
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str) or key in seen:
                raise yaml.YAMLError("duplicate or non-string YAML mapping key")
            seen.add(key)
        return cast(dict[str, Any], super().construct_mapping(node, deep=deep))


def _pnpm_locator(key: str) -> tuple[str, str, str]:
    locator = key.lstrip("/")
    peer_suffix = locator.find("(")
    if peer_suffix >= 0:
        if not locator.endswith(")") or not re.fullmatch(
            r"\([^()]+\)(?:\([^()]+\))*", locator[peer_suffix:]
        ):
            raise ValueError("invalid pnpm peer locator")
        locator = locator[:peer_suffix]
    if locator.startswith("@"):
        slash = locator.find("/")
        separator = locator.find("@", slash + 1) if slash >= 0 else -1
        if slash <= 1 or separator <= slash + 1:
            raise ValueError("invalid pnpm package locator")
    else:
        separator = locator.find("@")
        if separator <= 0:
            raise ValueError("invalid pnpm package locator")
    name, version = locator[:separator], locator[separator + 1 :]
    if not version or not _SAFE_VERSION.fullmatch(version):
        raise ValueError("invalid pnpm package version")
    if not (
        _SAFE_SCOPED_NAME.fullmatch(name)
        if name.startswith("@")
        else _SAFE_UNSCOPED_NAME.fullmatch(name)
    ):
        raise ValueError("invalid pnpm package name")
    return name, version, locator


def _pnpm_source_kind(metadata: Any) -> str:
    if not isinstance(metadata, dict):
        return "unknown"
    resolution = metadata.get("resolution")
    if not isinstance(resolution, dict):
        return "unknown"
    tarball = resolution.get("tarball")
    if not isinstance(tarball, str):
        return "unknown"
    return (
        "registry-npm"
        if _public_registry_url(tarball, "registry.npmjs.org", set())
        else "registry-other"
    )


def _parse_pnpm_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    event_count = 0
    started_at = time.monotonic()
    try:
        for event in yaml.parse(text, Loader=_StrictPnpmLoader):
            event_count += 1
            if (
                event_count > MAX_PNPM_YAML_EVENTS
                or time.monotonic() - started_at > MAX_SCAN_SECONDS
            ):
                raise ValueError("pnpm YAML resource limit exceeded")
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
                raise ValueError("pnpm YAML aliases and anchors are not supported")
        documents: list[Any] = []
        loader = _StrictPnpmLoader(text)
        try:
            while loader.check_data():
                if len(documents) >= 2:
                    raise ValueError("too many pnpm YAML documents")
                documents.append(loader.get_data())
        finally:
            loader.dispose()
    except yaml.YAMLError as error:
        raise ValueError("invalid pnpm YAML") from error
    if not documents or any(not isinstance(document, dict) for document in documents):
        raise ValueError("pnpm lockfile must contain mapping documents")

    unique: dict[tuple[str, str], Dependency] = {}
    for document in documents:
        if document.get("lockfileVersion") != "9.0":
            raise ValueError("unsupported pnpm lockfile version")
        importers = document.get("importers")
        packages = document.get("packages")
        snapshots = document.get("snapshots")
        if not all(isinstance(item, dict) for item in (importers, packages, snapshots)):
            raise ValueError("invalid pnpm lockfile structure")
        document_snapshots: dict[tuple[str, str], Any] = {}
        for snapshot_key, snapshot in snapshots.items():
            if not isinstance(snapshot_key, str) or not isinstance(snapshot, dict):
                raise ValueError("invalid pnpm snapshot")
            name, version, package_key = _pnpm_locator(snapshot_key)
            metadata = packages.get(package_key)
            if not isinstance(metadata, dict):
                raise ValueError("pnpm snapshot has no package metadata")
            identity = (name, version)
            document_snapshots[identity] = snapshot
            source_kind = _pnpm_source_kind(metadata)
            if identity in unique:
                previous = unique[identity]
                if previous.source_kind != source_kind:
                    unique[identity] = Dependency(name, version, "npm", path, "unknown")
            elif len(unique) >= limit:
                return list(unique.values()), True
            else:
                unique[identity] = Dependency(name, version, "npm", path, source_kind)

        def validate_reference(
            name: Any, version: Any, available: dict[tuple[str, str], Any]
        ) -> None:
            if not isinstance(name, str) or not isinstance(version, str) or not version:
                raise ValueError("invalid pnpm dependency reference")
            if version.startswith(("link:", "workspace:", "file:", "directory:")):
                return
            if version.startswith("npm:"):
                target = version.removeprefix("npm:")
                target_name, target_version, _ = _pnpm_locator(target)
            else:
                target_name, target_version, _ = _pnpm_locator(f"{name}@{version}")
            if (target_name, target_version) not in available:
                raise ValueError("pnpm dependency has no snapshot")

        dependency_sections = (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "configDependencies",
            "packageManagerDependencies",
        )
        for importer_path, importer in importers.items():
            if not isinstance(importer_path, str) or not isinstance(importer, dict):
                raise ValueError("invalid pnpm importer")
            for section in dependency_sections:
                references = importer.get(section, {})
                if not isinstance(references, dict):
                    raise ValueError("invalid pnpm importer dependencies")
                for package_name, reference in references.items():
                    if not isinstance(reference, dict):
                        raise ValueError("invalid pnpm importer dependency")
                    validate_reference(package_name, reference.get("version"), document_snapshots)

        for snapshot in document_snapshots.values():
            for section in ("dependencies", "optionalDependencies"):
                references = snapshot.get(section, {})
                if not isinstance(references, dict):
                    raise ValueError("invalid pnpm snapshot dependencies")
                for package_name, version in references.items():
                    validate_reference(package_name, version, document_snapshots)
    return list(unique.values()), False


def _parse_go_sum(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    records: list[Dependency] = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 3 or not fields[2]:
            raise ValueError("invalid go.sum record")
        name, version, _checksum = fields
        if version.endswith("/go.mod"):
            continue
        if len(records) >= limit:
            return records, True
        records.append(Dependency(name, version, "Go", path))
    return records, False


def _uv_source_kind(source: Any) -> str:
    if not isinstance(source, dict):
        return "unknown"
    registry = source.get("registry")
    if isinstance(registry, str):
        parsed = urlsplit(registry)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "pypi.org"
            and parsed.path.rstrip("/") == "/simple"
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and not parsed.query
            and not parsed.fragment
        ):
            return "registry-pypi"
        return "registry-other"
    for kind in ("git", "url", "directory", "editable", "virtual"):
        if kind in source:
            return kind
    return "unknown"


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate lockfile JSON key")
        result[key] = value
    return result


def _parse_composer_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    data = json.loads(text, object_pairs_hook=_strict_json_object)
    if not isinstance(data, dict):
        raise ValueError("invalid Composer lockfile")
    records: list[Dependency] = []
    seen: set[str] = set()
    for group in ("packages", "packages-dev"):
        packages = data.get(group)
        if not isinstance(packages, list):
            raise ValueError("missing Composer package list")
        for item in packages:
            if not isinstance(item, dict):
                raise ValueError("invalid Composer package")
            name, version = item.get("name"), item.get("version")
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}/[a-z0-9][a-z0-9_.-]{0,127}", name)
                or not isinstance(version, str)
                or not 1 <= len(version) <= 128
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+/-]*", version)
                or name in seen
            ):
                raise ValueError("invalid or duplicate Composer package identifier")
            seen.add(name)
            if len(records) >= limit:
                return records, True
            # Download/VCS URLs do not establish the originating registry.
            # Keep branch versions literal; never substitute aliases or requires.
            records.append(Dependency(name, version, "Packagist", path, "unknown"))
    return records, False


def _parse_pipfile_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    data = json.loads(text, object_pairs_hook=_strict_json_object)
    if not isinstance(data, dict) or not isinstance(data.get("_meta"), dict):
        raise ValueError("invalid Pipenv lockfile")
    meta = data["_meta"]
    if type(meta.get("pipfile-spec")) is not int or meta["pipfile-spec"] != 6:
        raise ValueError("unsupported Pipenv lockfile specification")
    sources = meta.get("sources")
    if not isinstance(sources, list):
        raise ValueError("invalid Pipenv sources")
    indexes: dict[str, str] = {}
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("invalid Pipenv source")
        name, url = source.get("name"), source.get("url")
        if (
            not isinstance(name, str)
            or not name
            or name in indexes
            or not isinstance(url, str)
            or type(source.get("verify_ssl")) is not bool
        ):
            raise ValueError("invalid or ambiguous Pipenv source")
        indexes[name] = (
            "registry-pypi"
            if source["verify_ssl"] is True and _public_registry_url(url, "pypi.org", {"/simple"})
            else "registry-other"
        )
    if not isinstance(data.get("default"), dict) or not isinstance(data.get("develop"), dict):
        raise ValueError("missing Pipenv package categories")
    records: list[Dependency] = []
    for category in sorted(key for key in data if key != "_meta"):
        packages = data[category]
        if not isinstance(packages, dict):
            raise ValueError("invalid Pipenv category")
        for name, item in packages.items():
            if not _SAFE_UNSCOPED_NAME.fullmatch(name) or not isinstance(item, dict):
                raise ValueError("invalid Pipenv package")
            version, index = item.get("version"), item.get("index")
            if (
                not isinstance(version, str)
                or not version.startswith("==")
                or not _SAFE_VERSION.fullmatch(version[2:])
                or (index is not None and (not isinstance(index, str) or index not in indexes))
            ):
                raise ValueError("Pipenv package lacks an exact version or valid index")
            if len(records) >= limit:
                return records, True
            source_kind = indexes[index] if isinstance(index, str) else "unknown"
            # A VCS/path/file entry cannot become public merely by adding an index.
            if any(key in item for key in ("git", "hg", "svn", "bzr", "path", "file", "editable")):
                source_kind = "unknown"
            records.append(Dependency(name, version[2:], "PyPI", path, source_kind))
    return records, False


_RUBY_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}"
_RUBY_VERSION = re.compile(r"^[0-9][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*$")
_RUBY_SPEC = re.compile(rf"^    ({_RUBY_NAME}) \(([^()\s]{{1,128}})\)$")
_RUBY_REF = re.compile(rf"^({_RUBY_NAME})(?: \(([^()]+)\))?(!)?$")


def _ruby_requirement_valid(value: str | None) -> bool:
    if value is None:
        return True
    return all(
        re.fullmatch(r"(?:~>|>=|<=|!=|>|<|=)?\s*[0-9][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*", part.strip())
        for part in value.split(",")
    )


def _parse_gemfile_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    """Conservative Bundler text inventory; never evaluate Gemfiles or sources."""
    # Unicode separators are not physical lockfile record delimiters.
    if any(separator in text for separator in ("\x85", "\u2028", "\u2029")):
        return [], True
    sections: list[tuple[str, list[str]]] = []
    incomplete = any(ord(char) < 32 and char not in "\n\r" for char in text)
    for line in text.splitlines():
        if not line:
            continue
        if not line.startswith(" "):
            sections.append((line, []))
        elif sections:
            sections[-1][1].append(line)
        else:
            incomplete = True
    specs: list[tuple[str, str, str, list[str]]] = []
    refs: list[tuple[str, bool]] = []
    checksums: list[tuple[str, str]] = []
    bundled_versions: list[str] = []
    seen_metadata: set[str] = set()
    seen_identities: set[tuple[str, str]] = set()
    references = 0
    registry_sections = sum(title == "GEM" for title, _ in sections)
    for title, lines in sections:
        if title in {"GEM", "GIT", "PATH"}:
            remotes: list[str] = []
            in_specs = False
            current: list[str] | None = None
            current_names: set[str] = set()
            headers: set[str] = set()
            kind = {"GEM": "registry-other", "GIT": "git", "PATH": "directory"}[title]
            pending: list[tuple[str, str, list[str]]] = []
            for line in lines:
                if line == "  specs:":
                    if in_specs:
                        incomplete = True
                    in_specs = True
                    continue
                if not in_specs:
                    match = re.fullmatch(r"  ([a-z_]+): (.+)", line)
                    if not match:
                        incomplete = True
                        continue
                    key, value = match.groups()
                    allowed = {
                        "GEM": {"remote"},
                        "GIT": {"remote", "revision", "branch", "ref", "tag", "submodules", "glob"},
                        "PATH": {"remote", "glob"},
                    }[title]
                    if key not in allowed or (key in headers and key != "remote"):
                        incomplete = True
                    if key == "revision" and not re.fullmatch(
                        r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value
                    ):
                        incomplete = True
                    if key == "submodules" and value not in {"true", "false"}:
                        incomplete = True
                    headers.add(key)
                    if key == "remote":
                        remotes.append(value)
                    continue
                match = _RUBY_SPEC.fullmatch(line)
                if match:
                    current = []
                    current_names = set()
                    name, version = match.groups()
                    if not re.fullmatch(
                        r"[0-9][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*(?:-[A-Za-z0-9][A-Za-z0-9_.-]{0,100})?",
                        version,
                    ):
                        incomplete = True
                        current = None
                        continue
                    if (name, version) in seen_identities:
                        incomplete = True
                    seen_identities.add((name, version))
                    if len(specs) + len(pending) >= limit:
                        incomplete = True
                        current = None
                        continue
                    pending.append((name, version, current))
                elif line.startswith("      ") and current is not None:
                    references += 1
                    if references > MAX_DEPENDENCIES * 10:
                        return [], True
                    dependency = _RUBY_REF.fullmatch(line[6:])
                    if (
                        dependency
                        and not dependency.group(3)
                        and _ruby_requirement_valid(dependency.group(2))
                    ):
                        if dependency.group(1) in current_names:
                            incomplete = True
                        current_names.add(dependency.group(1))
                        current.append(dependency.group(1))
                    else:
                        incomplete = True
                else:
                    incomplete = True
                    current = None
            if title == "GIT" and "revision" not in headers:
                incomplete = True
            if not in_specs or not remotes or (title != "GEM" and len(remotes) != 1):
                incomplete = True
            if (
                title == "GEM"
                and len(remotes) == 1
                and registry_sections == 1
                and remotes[0] in {"https://rubygems.org", "https://rubygems.org/"}
            ):
                kind = "registry-rubygems"
            for name, version, dependencies in pending:
                specs.append(
                    (
                        name,
                        version,
                        kind
                        if kind in {"git", "directory"} or _RUBY_VERSION.fullmatch(version)
                        else "unknown",
                        dependencies,
                    )
                )
        elif title in {"DEPENDENCIES", "PLATFORMS", "RUBY VERSION", "BUNDLED WITH", "CHECKSUMS"}:
            if title in seen_metadata:
                incomplete = True
            seen_metadata.add(title)
            if (not lines and title != "DEPENDENCIES") or (
                title in {"RUBY VERSION", "BUNDLED WITH"} and len(lines) != 1
            ):
                incomplete = True
            for line in lines:
                if title == "DEPENDENCIES":
                    references += 1
                    if references > MAX_DEPENDENCIES * 10:
                        return [], True
                    match = _RUBY_REF.fullmatch(line[2:]) if line.startswith("  ") else None
                    if match and _ruby_requirement_valid(match.group(2)):
                        refs.append((match.group(1), bool(match.group(3))))
                    else:
                        incomplete = True
                elif title == "CHECKSUMS":
                    references += 1
                    if references > MAX_DEPENDENCIES * 10:
                        return [], True
                    checksum = re.fullmatch(
                        rf"  ({_RUBY_NAME}) \(([^()\s]+)\)(?: sha256=[a-fA-F0-9]{{64}}(?:, sha256=[a-fA-F0-9]{{64}})*)?",
                        line,
                    )
                    if checksum:
                        checksums.append((checksum.group(1), checksum.group(2)))
                    else:
                        incomplete = True
                elif title == "PLATFORMS":
                    if not re.fullmatch(r"  [A-Za-z0-9_.-]+", line):
                        incomplete = True
                elif title == "BUNDLED WITH":
                    if not re.fullmatch(r" {2,3}[0-9][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*", line):
                        incomplete = True
                    else:
                        bundled_versions.append(line.strip())
                elif not re.fullmatch(
                    r" {2,3}ruby [0-9][A-Za-z0-9.]*(?:p[0-9]+)?(?: \([A-Za-z0-9 ._-]+\))?", line
                ):
                    incomplete = True
        else:
            incomplete = True
    incomplete |= len({name for name, _ in refs}) != len(refs)
    incomplete |= len(checksums) != len(set(checksums))
    incomplete |= len(bundled_versions) > 1
    incomplete |= any(
        (name, version) not in seen_identities
        and not (name == "bundler" and version in bundled_versions)
        for name, version in checksums
    )
    versions: dict[str, set[str]] = {}
    for name, version, _, _ in specs:
        if _RUBY_VERSION.fullmatch(version):
            versions.setdefault(name, set()).add(version)
    incomplete |= any(len(values) > 1 for values in versions.values())
    names = {name for name, _, _, _ in specs}
    nonregistry = {name for name, _, kind, _ in specs if kind in {"git", "directory"}}
    incomplete |= "DEPENDENCIES" not in seen_metadata or "PLATFORMS" not in seen_metadata
    incomplete |= any(
        name not in names or (pinned and name not in nonregistry) for name, pinned in refs
    )
    incomplete |= any(
        reference not in names for _, _, _, dependencies in specs for reference in dependencies
    )
    # Conflicting origins cannot safely establish public registry identity.
    origins: dict[str, set[str]] = {}
    for name, _, kind, _ in specs:
        origins.setdefault(name, set()).add(kind)
    return [
        Dependency(
            name,
            version,
            "RubyGems",
            path,
            kind
            if len(origins[name]) == 1 and not (incomplete and kind == "registry-rubygems")
            else "unknown",
        )
        for name, version, kind, _ in specs
    ], incomplete


_NUGET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
_NUGET_VERSION = re.compile(
    r"^[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?"
    r"(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?$"
)
_NUGET_TARGET = re.compile(
    r"^\.?[A-Za-z0-9][A-Za-z0-9.,= _+-]{0,255}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})?$"
)
_NUGET_FRAMEWORK = re.compile(r"^\.?[A-Za-z0-9][A-Za-z0-9.,= _+-]{0,255}$")
_NUGET_LOCK_NAME = re.compile(r"^packages\.[A-Za-z0-9_.-]{1,128}\.lock\.json$")


def _is_nuget_lock_name(name: str) -> bool:
    return name == "packages.lock.json" or bool(_NUGET_LOCK_NAME.fullmatch(name))


def _parse_nuget_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    """Inventory v1/v2/v3 pins without claiming a registry or evaluating MSBuild."""
    data = json.loads(text, object_pairs_hook=_strict_json_object)
    if not isinstance(data, dict) or type(data.get("version")) is not int:
        return [], True
    if data["version"] not in {1, 2, 3}:
        return [], True
    aliased = data["version"] == 3
    targets = (
        {key: value for key, value in data.items() if key != "version"}
        if aliased
        else data.get("dependencies")
    )
    if not isinstance(targets, dict):
        return [], True
    incomplete = not aliased and bool(set(data) - {"version", "dependencies"})
    records: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    graphs: dict[str, dict[str, Any]] = {}
    frameworks: dict[str, str] = {}
    entries = 0
    for target_index, (target, graph) in enumerate(targets.items()):
        if target_index >= MAX_LOCKFILES:
            return records, True
        if not _NUGET_TARGET.fullmatch(target) or not isinstance(graph, dict):
            incomplete = True
            continue
        if aliased:
            framework = graph.get("framework")
            if not isinstance(framework, str) or not _NUGET_FRAMEWORK.fullmatch(framework):
                incomplete = True
                continue
            frameworks[target] = framework.casefold()
            if set(graph) - {"framework", "dependencies"}:
                incomplete = True
            graph = graph.get("dependencies")
            if not isinstance(graph, dict):
                incomplete = True
                continue
        normalized: dict[str, Any] = {}
        for name, item in graph.items():
            entries += 1
            if entries > MAX_DEPENDENCIES:
                return records, True
            if (
                not _NUGET_NAME.fullmatch(name)
                or _SENSITIVE_NAME.match(name)
                or name.lower() in normalized
            ):
                incomplete = True
                continue
            normalized[name.lower()] = item
            if not isinstance(item, dict):
                incomplete = True
                continue
            kind = item.get("type")
            if not isinstance(kind, str) or kind not in {
                "Direct",
                "Transitive",
                "CentralTransitive",
                "Project",
            }:
                incomplete = True
                continue
            if set(item) - {"type", "requested", "resolved", "contentHash", "dependencies"}:
                incomplete = True
            for field in ("requested", "contentHash"):
                if field in item and (
                    not isinstance(item[field], str)
                    or not item[field]
                    or len(item[field]) > 512
                    or any(ord(char) < 32 for char in item[field])
                ):
                    incomplete = True
            version = item.get("resolved")
            if kind == "Project":
                if "resolved" in item and (
                    not isinstance(version, str)
                    or len(version) > 128
                    or not _NUGET_VERSION.fullmatch(version)
                ):
                    incomplete = True
                continue
            if (
                not isinstance(version, str)
                or len(version) > 128
                or not _NUGET_VERSION.fullmatch(version)
                or _SENSITIVE_VERSION_TOKEN.search(version)
            ):
                incomplete = True
                continue
            identity = (name.lower(), version)
            if identity not in seen:
                if len(records) >= limit:
                    return records, True
                seen.add(identity)
                records.append(Dependency(name, version, "NuGet", path, "unknown"))
        graphs[target] = normalized
    references = 0
    for target, graph in graphs.items():
        # RID graphs contain differences. V3 inherits by alias, not framework:
        # two aliases can intentionally name the same framework with different pins.
        base = target.split("/", 1)[0]
        matching_base = not aliased or frameworks.get(base) == frameworks.get(target)
        available = dict(graphs.get(base, {})) if matching_base else {}
        available.update(graph)
        if "/" in target and (base not in graphs or not matching_base):
            incomplete = True
        for item in graph.values():
            if not isinstance(item, dict):
                continue
            children = item.get("dependencies", {})
            if not isinstance(children, dict):
                incomplete = True
                continue
            names: set[str] = set()
            for name, constraint in children.items():
                references += 1
                if references > MAX_DEPENDENCIES * 10:
                    return records, True
                normalized_name = name.lower()
                if (
                    not _NUGET_NAME.fullmatch(name)
                    or normalized_name in names
                    or normalized_name not in available
                    or not isinstance(available.get(normalized_name), dict)
                    or not isinstance(constraint, str)
                    or not constraint
                    or len(constraint) > 512
                    or any(ord(char) < 32 for char in constraint)
                ):
                    incomplete = True
                names.add(normalized_name)
    return records, incomplete


_GRADLE_NAMES = {"gradle.lockfile", "buildscript-gradle.lockfile"}
_GRADLE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
_GRADLE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_GRADLE_CONFIGURATION = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}$")


def _is_gradle_lock_path(path: Path) -> bool:
    return path.name in _GRADLE_NAMES or (
        path.parent.name == "dependency-locks"
        and path.parent.parent.name == "gradle"
        and path.name.endswith(".lockfile")
        and bool(_GRADLE_CONFIGURATION.fullmatch(path.name.removesuffix(".lockfile")))
    )


def _parse_gradle_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    """Read recorded pins, never execute Gradle or infer a repository."""
    # Do not turn Unicode separators into additional valid records.
    if any(separator in text for separator in ("\x85", "\u2028", "\u2029")):
        return [], True
    legacy = Path(path).name not in _GRADLE_NAMES
    records: list[Dependency] = []
    incomplete = False
    seen: set[str] = set()
    occupied: dict[tuple[str, str], str] = {}
    populated: set[str] = set()
    empty: set[str] = set()
    empty_seen = False
    entries = edges = 0
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries += 1
        if entries > MAX_DEPENDENCIES + 1:
            return records, True
        if legacy:
            coordinate = line
            configurations = [Path(path).name.removesuffix(".lockfile")]
        else:
            if line.count("=") != 1:
                incomplete = True
                continue
            coordinate, value = line.split("=", 1)
            configurations = [item.strip() for item in value.split(",")] if value else []
        edges += len(configurations)
        if edges > MAX_DEPENDENCIES * 10:
            return records, True
        if len(configurations) != len(set(configurations)) or any(
            not _GRADLE_CONFIGURATION.fullmatch(item) for item in configurations
        ):
            incomplete = True
            continue
        if not legacy and coordinate == "empty":
            if empty_seen:
                incomplete = True
            empty_seen = True
            empty.update(configurations)
            continue
        parts = coordinate.split(":")
        if (
            len(parts) != 3
            or not configurations
            or not all(_GRADLE_COMPONENT.fullmatch(part) for part in parts[:2])
            or not _GRADLE_VERSION.fullmatch(parts[2])
            or parts[2].lower().startswith("latest.")
            or any(_SENSITIVE_NAME.match(part) for part in parts)
            or _SENSITIVE_VERSION_TOKEN.search(parts[2])
        ):
            incomplete = True
            continue
        if coordinate in seen:
            incomplete = True
            continue
        seen.add(coordinate)
        name = ":".join(parts[:2])
        for configuration in configurations:
            identity = (name, configuration)
            if identity in occupied and occupied[identity] != parts[2]:
                incomplete = True
            occupied[identity] = parts[2]
            populated.add(configuration)
        if len(records) >= limit:
            return records, True
        records.append(Dependency(name, parts[2], "Maven", path, "unknown"))
    if not legacy and (not empty_seen or empty & populated):
        incomplete = True
    return records, incomplete


_SWIFT_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?$"
)


class _StrictPubLoader(_StrictPnpmLoader):
    """Keep scalar versions as strings, but preserve plain YAML booleans."""

    yaml_implicit_resolvers: ClassVar[dict[Any, Any]] = {
        "t": [("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"))],
        "f": [("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"))],
    }


def _pub_opaque(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 4096
        and not any(ord(char) < 32 or char in "\x7f\x85\u2028\u2029" for char in value)
    )


def _pub_source_kind(source: Any, description: Any, name: str) -> str | None:
    """Validate opaque source metadata without opening or reporting its locations."""
    if source == "hosted":
        if isinstance(description, str):
            return "registry-other" if description == name else None
        if (
            not isinstance(description, dict)
            or set(description) - {"name", "url", "sha256"}
            or description.get("name") != name
            or not _pub_opaque(description.get("url"))
        ):
            return None
        if "sha256" in description and (
            not isinstance(description["sha256"], str)
            or not re.fullmatch(r"[a-fA-F0-9]{64}", description["sha256"])
        ):
            return None
        return "registry-other"
    if source == "git":
        if (
            not isinstance(description, dict)
            or set(description) - {"url", "ref", "resolved-ref", "path", "tag-pattern"}
            or not _pub_opaque(description.get("url"))
            or not isinstance(description.get("resolved-ref"), str)
            or not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", description["resolved-ref"])
            or ("ref" in description and "tag-pattern" in description)
            or any(
                not _pub_opaque(description[key])
                for key in ("ref", "path", "tag-pattern")
                if key in description
            )
        ):
            return None
        return "git"
    if source == "path":
        if (
            not isinstance(description, dict)
            or set(description) != {"path", "relative"}
            or not _pub_opaque(description.get("path"))
            or type(description.get("relative")) is not bool
        ):
            return None
        return "directory"
    if source == "sdk" and _pub_opaque(description):
        return "unknown"
    return None


def _parse_pub_lock(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    """Inventory exact pub lockfile versions without running Dart or Flutter."""
    count = 0
    started_at = time.monotonic()
    try:
        for event in yaml.parse(text, Loader=_StrictPubLoader):
            count += 1
            if count > MAX_PNPM_YAML_EVENTS or time.monotonic() - started_at > MAX_SCAN_SECONDS:
                raise ValueError("pub YAML resource limit exceeded")
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
                raise ValueError("pub YAML aliases and anchors are unsupported")
        data = yaml.load(text, Loader=_StrictPubLoader)
    except yaml.YAMLError as error:
        raise ValueError("invalid pub YAML") from error
    if not isinstance(data, dict) or not isinstance(data.get("packages"), dict):
        return [], True
    incomplete = bool(set(data) - {"packages", "sdks", "sdk"})
    if "sdks" in data and (
        not isinstance(data["sdks"], dict)
        or any(
            not _pub_opaque(key) or not _pub_opaque(value) for key, value in data["sdks"].items()
        )
    ):
        incomplete = True
    if "sdk" in data and not _pub_opaque(data["sdk"]):
        incomplete = True
    records: list[Dependency] = []
    for index, (name, package) in enumerate(data["packages"].items()):
        if index >= MAX_DEPENDENCIES:
            return records, True
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[_a-z][_a-z0-9]{0,255}", name)
            or _SENSITIVE_NAME.match(name)
            or not isinstance(package, dict)
        ):
            incomplete = True
            continue
        if set(package) - {"version", "source", "description", "dependency"}:
            incomplete = True
        if "dependency" in package and (
            not isinstance(package["dependency"], str)
            or package["dependency"]
            not in {"direct main", "direct dev", "direct overridden", "transitive"}
        ):
            incomplete = True
            continue
        version = package.get("version")
        kind = _pub_source_kind(package.get("source"), package.get("description"), name)
        if (
            not isinstance(version, str)
            or len(version) > 128
            or not _SWIFT_VERSION.fullmatch(version)
            or _SENSITIVE_VERSION_TOKEN.search(version)
            or any(
                part.isdigit() and len(part) > 1 and part.startswith("0")
                for part in version.split("+", 1)[0].partition("-")[2].split(".")
            )
            or kind is None
        ):
            incomplete = True
            continue
        if len(records) >= limit:
            return records, True
        records.append(Dependency(name, version, "Dart", path, kind))
    return records, incomplete


def _parse_swift_resolved(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    """Inventory v2/v3 identities without evaluating Swift or disclosing locations."""
    data = json.loads(text, object_pairs_hook=_strict_json_object)
    if not isinstance(data, dict) or type(data.get("version")) is not int:
        return [], True
    version = data["version"]
    if version not in {2, 3} or not isinstance(data.get("pins"), list):
        return [], True
    incomplete = bool(
        set(data) - ({"version", "pins", "originHash"} if version == 3 else {"version", "pins"})
    )
    origin_hash = data.get("originHash")
    if origin_hash is not None and (
        not isinstance(origin_hash, str)
        or len(origin_hash) > 512
        or any(ord(char) < 32 for char in origin_hash)
    ):
        incomplete = True
    records: list[Dependency] = []
    seen: set[str] = set()
    for index, pin in enumerate(data["pins"]):
        if index >= MAX_DEPENDENCIES:
            return records, True
        if not isinstance(pin, dict):
            incomplete = True
            continue
        identity = pin.get("identity")
        kind = pin.get("kind")
        location = pin.get("location")
        state = pin.get("state")
        if (
            not isinstance(identity, str)
            or not _SAFE_UNSCOPED_NAME.fullmatch(identity)
            or _SENSITIVE_NAME.match(identity)
            or identity.casefold() in seen
            or not isinstance(kind, str)
            or kind not in {"localSourceControl", "remoteSourceControl", "registry"}
            or not isinstance(location, str)
            or len(location) > 4096
            or (kind != "registry" and not location)
            or any(ord(char) < 32 for char in location)
            or not isinstance(state, dict)
        ):
            incomplete = True
            continue
        seen.add(identity.casefold())
        if set(pin) - {"identity", "kind", "location", "originalLocation", "state"}:
            incomplete = True
        original = pin.get("originalLocation")
        if original is not None and (
            not isinstance(original, str)
            or len(original) > 4096
            or any(ord(char) < 32 for char in original)
        ):
            incomplete = True
        if set(state) - {"version", "branch", "revision"}:
            incomplete = True
        release = state.get("version")
        revision = state.get("revision")
        branch = state.get("branch")
        if revision is not None and (
            not isinstance(revision, str)
            or not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", revision)
        ):
            incomplete = True
            continue
        if branch is not None and (
            not isinstance(branch, str)
            or not branch
            or len(branch) > 256
            or any(ord(char) < 32 for char in branch)
        ):
            incomplete = True
            continue
        if release is not None:
            if (
                not isinstance(release, str)
                or len(release) > 128
                or not _SWIFT_VERSION.fullmatch(release)
                or any(
                    part.isdigit() and len(part) > 1 and part.startswith("0")
                    for part in release.split("+", 1)[0].partition("-")[2].split(".")
                )
                or _SENSITIVE_VERSION_TOKEN.search(release)
                or branch is not None
                or (kind == "registry" and revision is not None)
            ):
                incomplete = True
                continue
            resolved = release
        else:
            # Branch/revision pins are not exact package release versions.
            incomplete = True
            continue
        if len(records) >= limit:
            return records, True
        records.append(Dependency(identity, resolved, "Swift", path, "unknown"))
    return records, incomplete


def _parse_lockfile(
    path: Path, relative: str, text: str, limit: int
) -> tuple[list[Dependency], bool]:
    if _is_gradle_lock_path(path):
        return _parse_gradle_lock(text, relative, limit)
    if path.name in {"requirements.txt", "requirements-lock.txt"}:
        return _parse_requirements(text, relative, limit)
    if path.name == "Gemfile.lock":
        return _parse_gemfile_lock(text, relative, limit)
    if path.name == "Package.resolved":
        return _parse_swift_resolved(text, relative, limit)
    if path.name == "pubspec.lock":
        return _parse_pub_lock(text, relative, limit)
    if _is_nuget_lock_name(path.name):
        return _parse_nuget_lock(text, relative, limit)
    if path.name == "yarn.lock":
        return _parse_yarn_lock(text, relative, limit)
    if path.name == "pnpm-lock.yaml":
        return _parse_pnpm_lock(text, relative, limit)
    if path.name == "composer.lock":
        return _parse_composer_lock(text, relative, limit)
    if path.name == "Pipfile.lock":
        return _parse_pipfile_lock(text, relative, limit)
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(text)
        records: list[Dependency] = []
        packages = data.get("packages", {}) if isinstance(data, dict) else {}
        if isinstance(packages, dict):
            for package_path, value in packages.items():
                if not package_path or not isinstance(value, dict):
                    continue
                name = package_path.rsplit("node_modules/", 1)[-1]
                version = value.get("version")
                if isinstance(version, str) and name:
                    if len(records) >= limit:
                        return records, True
                    records.append(
                        Dependency(
                            name, version, "npm", relative, _npm_source_kind(value.get("resolved"))
                        )
                    )
        if not records and isinstance(data, dict):
            return _walk_npm_dependencies(data.get("dependencies"), relative, limit)
        return records, False
    if path.name == "go.sum":
        return _parse_go_sum(text, relative, limit)
    if path.name in {"poetry.lock", "uv.lock", "Cargo.lock"}:
        data = tomllib.loads(text)
        ecosystem = "crates.io" if path.name == "Cargo.lock" else "PyPI"
        packages = data.get("package", [])
        if not isinstance(packages, list):
            return [], False
        toml_records: list[Dependency] = []
        for item in packages:
            if (
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and isinstance(item.get("version"), str)
            ):
                if len(toml_records) >= limit:
                    return toml_records, True
                if path.name == "uv.lock":
                    source_kind = _uv_source_kind(item.get("source"))
                elif path.name == "poetry.lock":
                    source_kind = _poetry_source_kind(item.get("source"))
                else:
                    source_kind = _cargo_source_kind(item.get("source"))
                toml_records.append(
                    Dependency(item["name"], item["version"], ecosystem, relative, source_kind)
                )
        return toml_records, False
    return [], False


class _LockfileLimitExceeded(ValueError):
    """Raised when a lockfile exceeds the remaining byte budget."""


def _read_bounded_lockfile(path: Path, remaining_bytes: int) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("lockfile is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("lockfile is not a regular file")
        if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("lockfile changed while opening")
        allowed = min(MAX_LOCKFILE_BYTES, remaining_bytes)
        if metadata.st_size > allowed:
            raise _LockfileLimitExceeded
        data = stream.read(allowed + 1)
        if len(data) > allowed or len(data) != metadata.st_size:
            raise ValueError("lockfile changed while reading")
    return data.decode("utf-8")


def _is_safe_osv_query(dependency: Dependency) -> bool:
    if dependency.ecosystem == "Go":
        valid_name = bool(_SAFE_GO_MODULE.fullmatch(dependency.name))
    else:
        valid_name = bool(
            _SAFE_SCOPED_NAME.fullmatch(dependency.name)
            if dependency.name.startswith("@")
            else _SAFE_UNSCOPED_NAME.fullmatch(dependency.name)
        )
    public_sources = {
        "PyPI": "registry-pypi",
        "npm": "registry-npm",
        "crates.io": "registry-cratesio",
        "Go": None,
        "RubyGems": "registry-rubygems",
    }
    return (
        dependency.ecosystem in public_sources
        and valid_name
        and dependency.source_kind == public_sources.get(dependency.ecosystem)
        and not _SENSITIVE_NAME.match(dependency.name)
        and bool(_SAFE_VERSION.fullmatch(dependency.version))
        and not _SENSITIVE_VERSION_TOKEN.search(dependency.version)
    )


def _post_osv_batch(dependencies: list[Dependency]) -> list[list[dict[str, Any]]]:
    if any(not _is_safe_osv_query(item) for item in dependencies):
        raise ValueError("OSV query contains an invalid package identifier")
    payload = {
        "queries": [
            {"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.version}
            for item in dependencies
        ]
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    if len(payload_bytes) > MAX_REQUEST_BYTES:
        raise ValueError("OSV request exceeded the configured size limit")
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload_bytes,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urlopen_no_redirect(request, timeout=5) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response exceeded the configured size limit")
    decoded = json.loads(body)
    results = decoded.get("results", []) if isinstance(decoded, dict) else []
    if not isinstance(results, list) or len(results) != len(dependencies):
        raise ValueError("OSV returned an unexpected batch response")
    return [item.get("vulns", []) if isinstance(item, dict) else [] for item in results]


def audit_dependencies(root: str | Path, *, query_osv: bool = False) -> DependencyReport:
    """Inventory supported lockfiles and optionally query OSV for exact versions."""
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("audit root must be a directory")
    supported = {
        "requirements.txt",
        "requirements-lock.txt",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
        "go.sum",
        "Gemfile.lock",
        "Package.resolved",
        "pubspec.lock",
    }
    dependencies: list[Dependency] = []
    errors: list[str] = []
    manifests = 0
    total_bytes = 0
    incomplete = False
    limit_reached = False
    started_at = time.monotonic()

    def record_walk_error(error: OSError) -> None:
        nonlocal incomplete
        filename = error.filename
        try:
            relative = Path(filename).relative_to(base).as_posix() if filename else "<unknown>"
        except ValueError:
            relative = "<unknown>"
        errors.append(f"{relative}: could not enumerate directory")
        incomplete = True

    for current, dirs, files in os.walk(base, followlinks=False, onerror=record_walk_error):
        if time.monotonic() - started_at >= MAX_SCAN_SECONDS:
            errors.append("scan time limit reached")
            incomplete = True
            break
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in {".git", ".venv", "venv", "node_modules"}
            and not (Path(current) / name).is_symlink()
        )
        for declaration, companions in _MANIFEST_COMPANIONS.items():
            if declaration in files and not any(
                companion in files and not (Path(current) / companion).is_symlink()
                for companion in companions
            ):
                declaration_path = Path(current) / declaration
                if declaration_path.is_symlink():
                    continue
                relative_declaration = declaration_path.relative_to(base).as_posix()
                errors.append(
                    f"{relative_declaration}: no supported companion lockfile; dependency coverage unknown"
                )
                incomplete = True
                if len(errors) >= MAX_LOCKFILES:
                    errors.append("uncovered manifest count reached configured limit")
                    limit_reached = True
                    break
        if limit_reached:
            break
        for declaration in sorted(files):
            if Path(declaration).suffix not in {".csproj", ".fsproj", ".vbproj"}:
                continue
            declaration_path = Path(current) / declaration
            if declaration_path.is_symlink():
                continue
            companions = {
                "packages.lock.json",
                f"packages.{Path(declaration).stem.replace(' ', '_')}.lock.json",
            }
            if not any(
                companion in files
                and _is_nuget_lock_name(companion)
                and not (Path(current) / companion).is_symlink()
                for companion in companions
            ):
                relative_declaration = declaration_path.relative_to(base).as_posix()
                errors.append(
                    f"{relative_declaration}: no supported companion lockfile; dependency coverage unknown"
                )
                incomplete = True
                if len(errors) >= MAX_LOCKFILES:
                    errors.append("uncovered manifest count reached configured limit")
                    limit_reached = True
                    break
        if limit_reached:
            break
        current_path = Path(current)
        if current_path.name == "dependency-locks" and current_path.parent.name == "gradle":
            project = current_path.parent.parent
            if any((project / modern).exists() for modern in _GRADLE_NAMES) and any(
                _is_gradle_lock_path(current_path / name) for name in files
            ):
                errors.append(
                    f"{current_path.relative_to(base).as_posix()}: mixed modern and legacy Gradle lock state; active precedence not inferred"
                )
                incomplete = True
        for name in sorted(files):
            if time.monotonic() - started_at >= MAX_SCAN_SECONDS:
                errors.append("scan time limit reached")
                incomplete = True
                break
            path = Path(current) / name
            if (
                name not in supported
                and not _is_nuget_lock_name(name)
                and not _is_gradle_lock_path(path)
            ) or path.is_symlink():
                continue
            if manifests >= MAX_LOCKFILES:
                errors.append("lockfile count reached configured limit")
                incomplete = True
                limit_reached = True
                break
            relative = path.relative_to(base).as_posix()
            try:
                text = _read_bounded_lockfile(path, MAX_TOTAL_BYTES - total_bytes)
                total_bytes += len(text.encode("utf-8"))
                manifests += 1
                remaining_dependencies = MAX_DEPENDENCIES - len(dependencies)
                parsed, truncated = _parse_lockfile(path, relative, text, remaining_dependencies)
                dependencies.extend(parsed)
                if name in {
                    "requirements.txt",
                    "requirements-lock.txt",
                } and _requirements_have_unresolved_entries(text):
                    errors.append(
                        f"{relative}: non-exact or unsupported requirements were not inventoried"
                    )
                    incomplete = True
                if truncated and name == "pubspec.lock":
                    errors.append(f"{relative}: unsupported, malformed, or bounded Dart inventory")
                    incomplete = True
                    continue
                if truncated and name == "Package.resolved":
                    errors.append(f"{relative}: unsupported, malformed, or bounded Swift inventory")
                    incomplete = True
                    continue
                if truncated and name == "Gemfile.lock":
                    errors.append(
                        f"{relative}: unsupported, malformed, unresolved, or bounded Bundler inventory"
                    )
                    incomplete = True
                    continue
                if truncated and _is_gradle_lock_path(path):
                    errors.append(
                        f"{relative}: unsupported, malformed, unresolved, or bounded Gradle inventory"
                    )
                    incomplete = True
                    continue
                if truncated and _is_nuget_lock_name(name):
                    errors.append(
                        f"{relative}: unsupported, malformed, unresolved, or bounded NuGet inventory"
                    )
                    incomplete = True
                    continue
                if truncated:
                    errors.append("dependency count reached configured limit")
                    incomplete = True
                    limit_reached = True
                    break
            except _LockfileLimitExceeded:
                errors.append(f"{relative}: skipped by size limit")
                incomplete = True
            except (OSError, ValueError, RecursionError):
                errors.append(f"{relative}: could not safely parse lockfile")
                incomplete = True
        if limit_reached:
            break

    unique = {(d.ecosystem, d.name, d.version, d.manifest, d.source_kind): d for d in dependencies}
    dependencies = sorted(
        unique.values(), key=lambda d: (d.ecosystem, d.name.lower(), d.version, d.manifest)
    )
    advisories: list[Advisory] = []
    lookup = "not_requested"
    if query_osv:
        lookup = "complete"
        max_queried = MAX_BATCH_SIZE * MAX_OSV_BATCHES
        if len(dependencies) > max_queried:
            lookup = "incomplete"
            errors.append(f"OSV lookup limited to the first {max_queried} dependencies")
        for offset in range(0, min(len(dependencies), max_queried), MAX_BATCH_SIZE):
            batch = dependencies[offset : offset + MAX_BATCH_SIZE]
            safe_batch = [item for item in batch if _is_safe_osv_query(item)]
            if len(safe_batch) != len(batch):
                skipped = len(batch) - len(safe_batch)
                lookup = "incomplete"
                errors.append(
                    f"OSV lookup skipped {skipped} dependencies without a recognized public source "
                    "or with invalid package identifiers"
                )
            if not safe_batch:
                continue
            try:
                results = _post_osv_batch(safe_batch)
                for dependency, vulns in zip(safe_batch, results, strict=True):
                    for vuln in vulns:
                        if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                            summary = vuln.get("summary")
                            advisories.append(
                                Advisory(
                                    dependency,
                                    vuln["id"],
                                    summary if isinstance(summary, str) else "",
                                )
                            )
            except (OSError, ValueError) as exc:
                lookup = "incomplete"
                errors.append(f"OSV lookup failed: {type(exc).__name__}")
    return DependencyReport(
        "incomplete" if incomplete or lookup == "incomplete" else "complete",
        manifests,
        tuple(dependencies),
        tuple(advisories),
        lookup,
        tuple(errors),
    )


def report_json(report: DependencyReport) -> str:
    payload = asdict(report)
    payload["schema_version"] = 1
    payload["report_type"] = "dependency_audit"
    return json.dumps(payload, indent=2, sort_keys=True)


def report_markdown(report: DependencyReport) -> str:
    lines = [
        "# Dependency audit",
        "",
        f"- Status: **{report.status}**",
        f"- Lockfiles scanned: **{report.manifests_scanned}**",
        f"- Dependencies inventoried: **{len(report.dependencies)}**",
        f"- OSV lookup: **{report.advisory_lookup}**",
        f"- Advisories: **{len(report.advisories)}**",
        "",
    ]
    if report.advisories:
        lines += [
            "| Advisory | Package | Version | Ecosystem | Lockfile | Summary |",
            "|---|---|---|---|---|---|",
        ]
        for item in report.advisories:
            d = item.dependency
            cells = (item.advisory_id, d.name, d.version, d.ecosystem, d.manifest, item.summary)
            safe_cells = [
                html.escape(cell, quote=False).replace("|", "\\|").replace("\n", " ")
                for cell in cells
            ]
            lines.append("| " + " | ".join(safe_cells) + " |")
    else:
        if not report.dependencies:
            lines.append("No supported lockfiles or exact dependency versions were found.")
        elif report.advisory_lookup == "complete":
            lines.append("No advisories were returned for the inventoried exact package versions.")
        else:
            lines.append("No advisories checked. Run with --query-osv to query OSV.dev.")
    if report.errors:
        lines += ["", "## Incomplete items", *[f"- {item}" for item in report.errors]]
    lines += [
        "",
        "Advisory lookup is best-effort; verify results against the upstream advisory before remediation.",
        "",
    ]
    return "\n".join(lines)
