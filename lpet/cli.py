#!/usr/bin/env python3
import argparse
import sys
from . import __version__
from .core.models import ScanContext
from .core.runner import scan
from .output.reports import write_json, write_html


BANNER = """LPET — Linux Privilege Escalation Exposure Scanner
Detection-only security assessment | version {version}
"""


def build_parser():
    p = argparse.ArgumentParser(prog="lpet", description="Detection-only Linux privilege-boundary scanner")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="run a security exposure scan")
    s.add_argument("--fast", action="store_true", help="skip broad filesystem permission scanning")
    s.add_argument("--root", action="append", default=["/"], help="scan root; may be repeated")
    s.add_argument("--json", default="reports/lpet-report.json")
    s.add_argument("--html", default="reports/lpet-report.html")
    s.add_argument("--max-findings", type=int, default=500)
    s.add_argument("--timeout", type=int, default=10)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        build_parser().print_help()
        return 0

    print(BANNER.format(version=__version__))
    print("[*] Authorized use only. No exploitation or system modification is performed.")
    ctx = ScanContext(
        fast=args.fast,
        roots=args.root,
        max_findings=args.max_findings,
        command_timeout=args.timeout,
    )
    report = scan(ctx)
    write_json(report, args.json)
    write_html(report, args.html)

    s = report["summary"]
    print("\nRisk Summary")
    for sev in ("critical", "high", "medium", "low", "info"):
        print(f"  {sev.upper():8} {s[sev]}")
    print(f"\nJSON : {args.json}")
    print(f"HTML : {args.html}")

    # CI-friendly exit behavior: non-zero for high/critical.
    return 2 if (s["critical"] or s["high"]) else 0


if __name__ == "__main__":
    sys.exit(main())
