from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .models import Severity
from .scanner import scan_repository


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oss-security-audit",
        description="Run a fast, local security baseline scan on a source repository.",
    )
    parser.add_argument("path", nargs="?", default=".", help="repository directory (default: current directory)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="exit 1 when a finding reaches this severity (default: high)",
    )
    parser.add_argument("--exclude", action="append", default=[], help="directory name to skip; repeatable")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        summary = scan_repository(args.path, tuple(args.exclude))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "tool": "oss-security-audit",
            "version": __version__,
            "path": args.path,
            "files_scanned": summary.files_scanned,
            "findings": [finding.to_dict() for finding in summary.findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Scanned {summary.files_scanned} files.")
        if not summary.findings:
            print("No baseline findings.")
        for finding in summary.findings:
            location = f":{finding.line}" if finding.line else ""
            print(
                f"{finding.severity.name:<8} {finding.rule_id:<10} "
                f"{finding.path}{location} — {finding.message}"
            )

    if args.fail_on == "none":
        return 0
    threshold = Severity[args.fail_on.upper()]
    return 1 if any(finding.severity >= threshold for finding in summary.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
