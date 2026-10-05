"""Command-line entry point; all commands are read-only in v0.1.0."""

import argparse
import sys

from .domain import RepositoryTarget
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

    local_parser = sub.add_parser(
        "scan-local", help="scan a local repository without executing it"
    )
    local_parser.add_argument("path", nargs="?", default=".")
    local_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
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

    target = RepositoryTarget(args.owner, args.repo, args.base_branch)
    findings = scan(target, EmptyProvider())
    renderer = report_json if args.format == "json" else report_markdown
    sys.stdout.write(renderer(target, findings))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
