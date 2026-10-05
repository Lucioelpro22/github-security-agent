"""Command-line entry point; all commands are read-only in v0.1.0."""

import argparse
import os
import re
import sys

from .dependency_audit import audit_dependencies
from .dependency_audit import report_json as dependency_report_json
from .dependency_audit import report_markdown as dependency_report_markdown
from .domain import RepositoryTarget
from .github_provider import GitHubApiProvider, GitHubProviderError
from .provider import EmptyProvider
from .repository_scan import report_json as local_report_json
from .repository_scan import report_markdown as local_report_markdown
from .repository_scan import scan_repository
from .service import report_json, report_markdown, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only GitHub security inventory")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("scan", "plan"):
        command_parser = sub.add_parser(command, help="inspect findings without remote writes")
        command_parser.add_argument("--owner", required=True)
        command_parser.add_argument("--repo", required=True)
        command_parser.add_argument("--base-branch", default="main")
        command_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
        command_parser.add_argument(
            "--provider",
            choices=("empty", "github"),
            default="empty",
            help="use the offline empty provider (default) or read-only GitHub alerts",
        )
        command_parser.add_argument(
            "--token-env",
            default="GITHUB_TOKEN",
            help="environment variable containing the read-only GitHub token",
        )

    local_parser = sub.add_parser("scan-local", help="scan a local repository without executing it")
    local_parser.add_argument("path", nargs="?", default=".")
    local_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    dependency_parser = sub.add_parser(
        "audit-dependencies", help="inventory lockfiles and optionally query OSV.dev"
    )
    dependency_parser.add_argument("path", nargs="?", default=".")
    dependency_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    dependency_parser.add_argument(
        "--query-osv",
        action="store_true",
        help="send package names, ecosystems, and exact versions to OSV.dev",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan-local":
        try:
            report = scan_repository(args.path)
        except (OSError, ValueError):
            sys.stderr.write(
                "Unable to scan the selected path. Check that it is a readable directory.\n"
            )
            return 2
        renderer = local_report_json if args.format == "json" else local_report_markdown
        sys.stdout.write(renderer(report))
        return 0 if report.status == "complete" else 2

    if args.command == "audit-dependencies":
        try:
            dependency_report = audit_dependencies(args.path, query_osv=args.query_osv)
        except (OSError, ValueError):
            sys.stderr.write(
                "Unable to audit the selected path. Check that it is a readable directory.\n"
            )
            return 2
        dependency_renderer = (
            dependency_report_json if args.format == "json" else dependency_report_markdown
        )
        sys.stdout.write(dependency_renderer(dependency_report))
        return 0 if dependency_report.status == "complete" else 2

    target = RepositoryTarget(args.owner, args.repo, args.base_branch)
    if args.provider == "github":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.token_env):
            sys.stderr.write("Invalid token environment variable name.\n")
            return 2
        token = os.environ.get(args.token_env)
        if not token or not token.strip():
            sys.stderr.write(f"Required environment variable {args.token_env} is not set.\n")
            return 2
        provider = GitHubApiProvider(token)
    else:
        provider = EmptyProvider()
    try:
        findings = scan(target, provider)
    except (GitHubProviderError, ValueError) as exc:
        sys.stderr.write(f"GitHub scan incomplete: {exc}.\n")
        return 2
    if args.format == "json":
        sys.stdout.write(report_json(target, findings))
    else:
        sys.stdout.write(report_markdown(target, findings))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
