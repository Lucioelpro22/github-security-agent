"""Safe CLI: local scanning only, no shell, no write operations."""

import argparse
import json
from pathlib import Path

from .models import ScanPolicy
from .redaction import redact
from .scanner import scan_directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only offline repository security scan")
    parser.add_argument("root", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        findings = scan_directory(args.root, ScanPolicy())
    except (OSError, ValueError) as exc:
        print(redact(f"scan failed: {exc}"))
        return 2
    payload = [finding.safe_dict() for finding in findings]
    print(json.dumps(payload, indent=2) if args.as_json else f"{len(payload)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
