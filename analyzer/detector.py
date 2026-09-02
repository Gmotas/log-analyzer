"""
analyzer/detector — heuristic-based suspicious-activity detection.

The detector scans a stream of :class:`~analyzer.parser.LogRecord` objects and
emits :class:`Finding` objects. Each finding carries a type, a severity
(1-5, low-to-critical), the affected source, and the evidence lines that
triggered it.

Heuristics implemented:

* brute_force    — repeated failed auth attempts from one source in a window.
* port_scan      — one source probing many distinct ports (seen as distinct
                   request/connects) in a window.
* injection      — SQLi / XSS / traversal indicators in request paths or queries.
* suspicious_ua  — known-bad user agents (optional).
* blacklist      — source IP on a configured block list.
* request_burst  — request-volume spike above a per-source baseline.

All thresholds are configurable via :class:`DetectorConfig`.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from analyzer.parser import LogRecord

# Severity levels
LOW, MEDIUM, HIGH, CRITICAL = 1, 2, 3, 5

SEVERITY_NAMES = {
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical",
}

# --- Signal regexes --------------------------------------------------------
_SQLI_PATTERNS = [
    re.compile(r"(?i)(union\s+select)", re.IGNORECASE),
    re.compile(r"(?i)(sleep\s*\()", re.IGNORECASE),
    re.compile(r"(?i)(information_schema)", re.IGNORECASE),
    re.compile(r"(?i)(\bor\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
    re.compile(r"(?i)(\bselect\b.+\bfrom\b)"),
]

_XSS_PATTERNS = [
    re.compile(r"(?i)(<script)"),
    re.compile(r"(?i)(javascript:)"),
    re.compile(r"(?i)(onerror\s*=)"),
]

_TRAVERSAL_PATTERNS = [
    re.compile(r"(?i)(\.\./)"),
    re.compile(r"(?i)(/etc/passwd)"),
    re.compile(r"(?i)(boot\.ini)"),
]

_BAD_UA_PATTERNS = [
    re.compile(r"(?i)(sqlmap)"),
    re.compile(r"(?i)(nikto)"),
    re.compile(r"(?i)(masscan)"),
    re.compile(r"(?i)(nmap)"),
]

_AUTH_FAIL_KEYWORDS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed to authenticate",
    "password mismatch",
    "login failed",
)


@dataclass
class DetectorConfig:
    """Tunable detection thresholds."""

    window_seconds: int = 300
    max_failed_attempts: int = 5
    scan_port_threshold: int = 20
    burst_factor: float = 4.0
    burst_min_requests: int = 40
    blacklist: set[str] = field(default_factory=set)


@dataclass
class Finding:
    """A single suspicious-activity detection."""

    type: str
    severity: int
    source: str | None
    summary: str
    evidence: list[str] = field(default_factory=list)
    ts: datetime | None = None
    count: int = 1

    @property
    def label(self) -> str:
        return SEVERITY_NAMES.get(self.severity, "unknown")


class Detector:
    """Stateful detector that consumes records over time."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self.findings: list[Finding] = []
        self._recent: dict[str, deque[tuple[datetime | None, LogRecord]]] = defaultdict(deque)
        self._port_counts: dict[str, set] = defaultdict(set)
        self._source_request_counts: Counter[str] = Counter()
        self._source_windows: dict[str, deque[datetime | None]] = defaultdict(deque)
        self._current = self.config.window_seconds and datetime.now() or None

    # --- public API --------------------------------------------------------
    def add(self, record: LogRecord) -> None:
        """Feed one record and update all heuristic state."""
        self._collect(record)
        self._detect_injection(record)
        self._detect_blacklist(record)
        self._detect_bad_ua(record)
        # Time-windowed checks run on the aggregated state.
        self._detect_brute_force(record)
        self._detect_port_scan(record)
        self._detect_burst(record)

    def analyze(self, records: Iterable[LogRecord]) -> list[Finding]:
        """Convenience: feed many records and return findings."""
        for record in records:
            self.add(record)
        return self.findings

    # --- state collection --------------------------------------------------
    def _collect(self, record: LogRecord) -> None:
        source = record.source or "unknown"
        if record.ts is None:
            # Use a synthetic clock so windowed checks still function when logs
            # omit timestamps.
            self._current = (self._current or datetime.now()) + timedelta(seconds=1)
            ts = self._current
        else:
            ts = record.ts
        self._recent[source].append((ts, record))
        self._source_windows[source].append(ts)
        self._source_request_counts[source] += 1

        # Port scan: count distinct destination ports per source. For HTTP
        # records we approximate "port" by the first path segment when a
        # status is present (a probe often hits the server root repeatedly).
        if record.path and record.method:
            seg = record.path.split("/")
            port_key = seg[1] if len(seg) > 1 and seg[1] else "(root)"
            self._port_counts[source].add(port_key)
        elif record.service:
            self._port_counts[source].add(record.service)

        self._expire_window(source, ts)

    def _expire_window(self, source: str, now: datetime | None) -> None:
        if now is None:
            return
        cutoff = now - timedelta(seconds=self.config.window_seconds)
        win = self._recent[source]
        while win and win[0][0] and win[0][0] < cutoff:
            win.popleft()
        ww = self._source_windows[source]
        while ww and ww[0] and ww[0] < cutoff:
            ww.popleft()

    # --- individual heuristics --------------------------------------------
    def _detect_injection(self, record: LogRecord) -> None:
        text = " ".join(filter(None, [record.path, record.message, record.extra.get("query", "")]))
        if not text:
            return
        kind = None
        for pat in _SQLI_PATTERNS:
            if pat.search(text):
                kind = "sql-injection"
                break
        if kind is None:
            for pat in _XSS_PATTERNS:
                if pat.search(text):
                    kind = "xss"
                    break
        if kind is None:
            for pat in _TRAVERSAL_PATTERNS:
                if pat.search(text):
                    kind = "path-traversal"
                    break
        if kind is None:
            return
        self.findings.append(Finding(
            type=kind,
            severity=HIGH,
            source=record.source,
            summary=f"{kind}: suspicious pattern in request",
            evidence=[record.raw],
            ts=record.ts,
        ))

    def _detect_bad_ua(self, record: LogRecord) -> None:
        ua = str(record.extra.get("user_agent", ""))
        if not ua:
            return
        for pat in _BAD_UA_PATTERNS:
            if pat.search(ua):
                self.findings.append(Finding(
                    type="known-scanner-ua",
                    severity=MEDIUM,
                    source=record.source,
                    summary="request from a known scanner/attack user-agent",
                    evidence=[record.raw],
                    ts=record.ts,
                ))
                break

    def _detect_blacklist(self, record: LogRecord) -> None:
        if record.source and record.source in self.config.blacklist:
            self.findings.append(Finding(
                type="blacklisted-ip",
                severity=CRITICAL,
                source=record.source,
                summary="source IP is on the configured blacklist",
                evidence=[record.raw],
                ts=record.ts,
            ))

    def _detect_brute_force(self, record: LogRecord) -> None:
        if not record.service or not record.message:
            return
        if not any(kw in record.message.lower() for kw in _AUTH_FAIL_KEYWORDS):
            return
        source = record.source or "unknown"
        window = [r for r in self._recent[source] if r[1] is not None and self._is_failed(r[1])]
        if len(window) >= self.config.max_failed_attempts:
            # De-duplicate: only emit once per source, refreshing evidence.
            existing = [f for f in self.findings if f.type == "brute-force" and f.source == source]
            if not existing:
                self.findings.append(Finding(
                    type="brute-force",
                    severity=HIGH,
                    source=source,
                    summary=f"{len(window)} failed authentication attempts in window",
                    evidence=[r[1].raw for r in window[-self.config.max_failed_attempts:]],
                    ts=record.ts,
                    count=len(window),
                ))
            else:
                existing[0].count = len(window)
                existing[0].evidence = [r[1].raw for r in window[-self.config.max_failed_attempts:]]

    @staticmethod
    def _is_failed(record: LogRecord) -> bool:
        if not record.message:
            return False
        return any(kw in record.message.lower() for kw in _AUTH_FAIL_KEYWORDS)

    def _detect_port_scan(self, record: LogRecord) -> None:
        source = record.source or "unknown"
        ports = self._port_counts[source]
        if len(ports) >= self.config.scan_port_threshold:
            existing = [f for f in self.findings if f.type == "port-scan" and f.source == source]
            if not existing:
                self.findings.append(Finding(
                    type="port-scan",
                    severity=MEDIUM,
                    source=source,
                    summary=f"{len(ports)} distinct ports/probes from source in window",
                    evidence=[record.raw],
                    ts=record.ts,
                    count=len(ports),
                ))
            else:
                existing[0].count = len(ports)

    def _detect_burst(self, record: LogRecord) -> None:
        source = record.source or "unknown"
        # Baseline is the average requests per source across the whole session.
        baseline = self._mean_requests()
        count = self._source_request_counts[source]
        if baseline > 0 and count >= self.config.burst_min_requests and count >= baseline * self.config.burst_factor:
            existing = [f for f in self.findings if f.type == "request-burst" and f.source == source]
            if not existing:
                self.findings.append(Finding(
                    type="request-burst",
                    severity=MEDIUM,
                    source=source,
                    summary=f"request rate {count} vs baseline {baseline:.1f} for source",
                    evidence=[record.raw],
                    ts=record.ts,
                    count=count,
                ))
            else:
                existing[0].count = count

    def _mean_requests(self) -> float:
        if not self._source_request_counts:
            return 0.0
        return sum(self._source_request_counts.values()) / len(self._source_request_counts)

    def dedupe(self) -> list[Finding]:
        """Return findings sorted by severity (desc), highest first."""
        return sorted(self.findings, key=lambda f: (f.severity, f.ts or datetime.min), reverse=True)
