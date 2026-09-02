"""
analyzer/reporter — human-readable and machine-readable reporting.

Turns a list of :class:`~analyzer.detector.Finding` objects (plus a small set
of run statistics) into either a colorized console report or a JSON payload.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from analyzer.detector import Finding

# ANSI color helpers (colors degrade gracefully when piped / disabled).
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_GREEN = "\033[92m"
_GRAY = "\033[90m"

_SEV_COLOR = {
    1: _GREEN,
    2: _YELLOW,
    3: _YELLOW,
    5: _RED,
}

SEV_LABEL = {1: "low", 2: "medium", 3: "high", 5: "critical"}
CRITICAL, HIGH, MEDIUM, LOW = 5, 3, 2, 1


def _paint(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{_RESET}" if use_color else text


def build_summary(findings: list[Finding]) -> dict[str, Any]:
    """Build a JSON-friendly structure for the whole analysis."""
    by_type = Counter(f.type for f in findings)
    by_sev = Counter(f.severity for f in findings)
    sources = Counter(f.source for f in findings if f.source)
    return {
        "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        "total_findings": len(findings),
        "by_severity": {str(k): v for k, v in sorted(by_sev.items(), reverse=True)},
        "by_type": dict(by_type),
        "top_sources": dict(sources.most_common(10)),
        "findings": [
            {
                "type": f.type,
                "severity": f.severity,
                "level": f.label,
                "source": f.source,
                "summary": f.summary,
                "count": f.count,
                "timestamp": f.ts.isoformat(timespec="seconds") if f.ts else None,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }


def render_report(findings: list[Finding], use_color: bool = True) -> str:
    """Render the console report for all findings."""
    if not findings:
        return _paint("[+] No suspicious activity detected.\n", _GREEN, use_color)

    lines: list[str] = []
    lines.append(_paint("Security Log Analysis Report", _BOLD + _BLUE, use_color))
    lines.append(_paint("=" * 46, _GRAY, use_color))
    lines.append(_paint(f"Findings: {len(findings)}", _BOLD, use_color))

    by_sev = Counter(f.severity for f in findings)
    for sev in (CRITICAL, HIGH, MEDIUM, LOW):
        if by_sev.get(sev):
            lines.append(
                _paint(f"  {SEV_LABEL[sev]:<10}: {by_sev[sev]}", _SEV_COLOR.get(sev, _GRAY), use_color)
            )

    lines.append("")
    for idx, f in enumerate(findings, start=1):
        color = _SEV_COLOR.get(f.severity, _GRAY)
        tag = f"[{f.severity}]"
        head = f"{idx:>2}. {tag} {f.type.upper()} ({SEV_LABEL[f.severity]})"
        lines.append(_paint(head, color, use_color))
        where = f"  source: {f.source or 'unknown'}"
        if f.count > 1:
            where += f"  count: {f.count}"
        if f.ts:
            where += f"  at: {f.ts.isoformat(timespec='seconds')}"
        lines.append(_paint(where, _GRAY, use_color))
        lines.append(_paint(f"  {f.summary}", _GRAY, use_color))
        for ev in f.evidence[:3]:
            lines.append(_paint(f"    | {ev}", _GRAY, use_color))
        lines.append("")

    lines.append(_paint("[-] Analysis complete.", _BOLD, use_color))
    return "\n".join(lines) + "\n"


def findings_from_summary(summary: dict[str, Any]) -> list[Finding]:
    """Rebuild Finding objects from a JSON summary (used for --json round-trips)."""
    out: list[Finding] = []
    for item in summary.get("findings", []):
        ts = None
        if item.get("timestamp"):
            try:
                ts = datetime.fromisoformat(item["timestamp"])
            except ValueError:
                ts = None
        out.append(Finding(
            type=item["type"],
            severity=int(item["severity"]),
            source=item.get("source"),
            summary=item["summary"],
            evidence=item.get("evidence", []),
            ts=ts,
            count=int(item.get("count", 1)),
        ))
    return out


def render_json(summary: dict[str, Any]) -> str:
    """Serialize the summary to a compact JSON string."""
    return json.dumps(summary, indent=2, ensure_ascii=False)
