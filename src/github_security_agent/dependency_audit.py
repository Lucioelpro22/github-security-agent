"""Opt-in dependency inventory and OSV.dev advisory lookup.

The default audit is fully local. Network requests are made only when the caller
explicitly enables advisory lookup; only package names, ecosystems, and exact
versions are sent, never source files or lockfile contents.
"""

from __future__ import annotations

import html
import json
import os
import re
import stat
import tomllib
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

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


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest: str


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


def _parse_requirements(text: str, path: str, limit: int) -> tuple[list[Dependency], bool]:
    records: list[Dependency] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        match = _PINNED.fullmatch(line)
        if match:
            if len(records) >= limit:
                return records, True
            records.append(Dependency(match.group(1), match.group(2), "PyPI", path))
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
                records.append(Dependency(name, version, "npm", path))
            nested = value.get("dependencies")
            if isinstance(nested, dict):
                pending.append(nested)
    return records, False


def _parse_lockfile(
    path: Path, relative: str, text: str, limit: int
) -> tuple[list[Dependency], bool]:
    if path.name in {"requirements.txt", "requirements-lock.txt"}:
        return _parse_requirements(text, relative, limit)
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
                    records.append(Dependency(name, version, "npm", relative))
        if not records and isinstance(data, dict):
            return _walk_npm_dependencies(data.get("dependencies"), relative, limit)
        return records, False
    if path.name in {"poetry.lock", "Cargo.lock"}:
        data = tomllib.loads(text)
        ecosystem = "PyPI" if path.name == "poetry.lock" else "crates.io"
        packages = data.get("package", [])
        if not isinstance(packages, list):
            return [], False
        records: list[Dependency] = []
        for item in packages:
            if (
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and isinstance(item.get("version"), str)
            ):
                if len(records) >= limit:
                    return records, True
                records.append(
                    Dependency(item["name"], item["version"], ecosystem, relative)
                )
        return records, False
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


def _post_osv_batch(dependencies: list[Dependency]) -> list[list[dict[str, Any]]]:
    payload = {
        "queries": [
            {"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.version}
            for item in dependencies
        ]
    }
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
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
        "poetry.lock",
        "Cargo.lock",
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
        for name in sorted(files):
            if time.monotonic() - started_at >= MAX_SCAN_SECONDS:
                errors.append("scan time limit reached")
                incomplete = True
                break
            path = Path(current) / name
            if name not in supported or path.is_symlink():
                continue
            if manifests >= MAX_LOCKFILES:
                incomplete = True
                break
            relative = path.relative_to(base).as_posix()
            try:
                text = _read_bounded_lockfile(path, MAX_TOTAL_BYTES - total_bytes)
                total_bytes += len(text.encode("utf-8"))
                manifests += 1
                remaining_dependencies = MAX_DEPENDENCIES - len(dependencies)
                parsed, truncated = _parse_lockfile(
                    path, relative, text, remaining_dependencies
                )
                dependencies.extend(parsed)
                if truncated:
                    errors.append("dependency count reached configured limit")
                    incomplete = True
                    limit_reached = True
                    break
            except _LockfileLimitExceeded:
                errors.append(f"{relative}: skipped by size limit")
                incomplete = True
            except (OSError, UnicodeError, ValueError, RecursionError):
                errors.append(f"{relative}: could not safely parse lockfile")
                incomplete = True
        if manifests >= MAX_LOCKFILES:
            errors.append("lockfile count reached configured limit")
            incomplete = True
            break
        if limit_reached:
            break

    unique = {(d.ecosystem, d.name, d.version, d.manifest): d for d in dependencies}
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
            try:
                results = _post_osv_batch(batch)
                for dependency, vulns in zip(batch, results, strict=True):
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
            except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
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
    return json.dumps(asdict(report), indent=2, sort_keys=True)


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
