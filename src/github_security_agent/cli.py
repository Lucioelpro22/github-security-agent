"""Command-line entry point; all commands are read-only in v0.1.0."""

import argparse
import sys

from .domain import RepositoryTarget
from .provider import EmptyProvider
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = RepositoryTarget(args.owner, args.repo, args.base_branch)
    findings = scan(target, EmptyProvider())
    if args.format == "json":
        sys.stdout.write(report_json(target, findings))
    else:
        sys.stdout.write(report_markdown(target, findings))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
