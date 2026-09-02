#!/usr/bin/env python3
"""
Log Analyzer — parse server logs and detect suspicious activity.

A CLI security tool that ingests Apache/nginx combined access logs, syslog-like
key=value lines and /var/log/auth.log style entries, then flags suspicious
activity (brute force, port scan, injection, known scanners, blacklisted IPs,
request bursts) with a severity rating.

Usage examples:
    python log_analyzer.py examples/sample.log
    python log_analyzer.py --json auth.log
    cat access.log | python log_analyzer.py --stdin
    python log_analyzer.py examples/sample.log --min-severity 3 --quiet

Exit codes: 0 = clean, 1 = findings detected, 2 = usage/parse error.
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable

import analyzer.parser as parser_mod
from analyzer.detector import CRITICAL, HIGH, LOW, MEDIUM, Detector, DetectorConfig, Finding
from analyzer.reporter import build_summary, render_json, render_report

__version__ = "1.0.0"
__author__ = "Gabriel Mota Silva"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Parse server logs and detect suspicious activity.",
        epilog="Exit codes: 0 = clean, 1 = findings detected, 2 = usage/parse error.",
    )
    ap.add_argument("files", nargs="*", help="Log file(s) to analyze (default: read from --stdin).")
    ap.add_argument("--stdin", action="store_true", help="Read log lines from standard input.")
    ap.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report.")
    ap.add_argument("--quiet", action="store_true", help="Suppress non-report output.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors in the report.")
    ap.add_argument("--window", type=int, default=300, help="Detection time window in seconds (default 300).")
    ap.add_argument("--threshold", type=int, default=5, help="Failed-auth threshold for brute force (default 5).")
    ap.add_argument("--scan-ports", type=int, default=20, help="Distinct ports per source to flag a scan (default 20).")
    ap.add_argument("--burst-min", type=int, default=40, help="Min requests before burst detection (default 40).")
    ap.add_argument("--burst-factor", type=float, default=4.0, help="Multiplier over baseline to flag a burst (default 4).")
    ap.add_argument("--min-severity", type=int, choices=[LOW, MEDIUM, HIGH, CRITICAL], default=LOW,
                    help="Minimum severity to report (default 1).")
    ap.add_argument("--noise-ip", action="append", default=[], metavar="IP",
                    help="IP address to ignore (repeatable).")
    ap.add_argument("--blacklist", action="append", default=[], metavar="IP",
                    help="IP address to always flag as suspicious (repeatable).")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args(argv)


def iter_lines(args: argparse.Namespace) -> Iterable[str]:
    """Yield raw log lines from the chosen source(s)."""
    if args.files:
        for path in args.files:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    yield from fh
            except OSError as exc:
                print(f"error: cannot read {path}: {exc}", file=sys.stderr)
    elif args.stdin:
        yield from sys.stdin
    else:
        print("error: provide one or more log files, or use --stdin", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    config = DetectorConfig(
        window_seconds=args.window,
        max_failed_attempts=args.threshold,
        scan_port_threshold=args.scan_ports,
        burst_min_requests=args.burst_min,
        burst_factor=args.burst_factor,
        blacklist=set(args.blacklist),
    )
    noise = set(args.noise_ip)
    detector = Detector(config)

    parsed = 0
    skipped = 0
    for line in iter_lines(args):
        if line.strip() == "":
            continue
        try:
            record = parser_mod.parse_line(line)
        except parser_mod.ParseError:
            skipped += 1
            continue
        if record.source in noise:
            continue
        parsed += 1
        detector.add(record)

    # Deduplicate and filter by severity.
    findings = [f for f in detector.dedupe() if f.severity >= args.min_severity]
    summary = build_summary(findings)
    summary["lines_parsed"] = parsed
    summary["lines_skipped"] = skipped

    if args.json:
        print(render_json(summary))
    else:
        if not args.quiet:
            print(render_report(findings, use_color=not args.no_color))
            print(f"parsed: {parsed} lines, skipped: {skipped} malformed lines")
        else:
            # Quiet mode: print only the verdict line.
            verdict = "CLEAN" if not findings else "SUSPICIOUS"
            print(verdict)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
