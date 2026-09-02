"""
analyzer/parser — tolerant, format-aware log line parsing.

The Log Analyzer reads Apache/nginx combined access logs, common syslog /
key=value lines, and a generic format. This module turns raw log lines into
normalized :class:`LogRecord` objects.

Only the Python standard library is used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Apache / nginx combined log format.
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
COMBINED_RE = re.compile(
    r'(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)

# nginx sometimes adds a referer and user-agent after the request line;
# the combined regex above simply ignores trailing tokens, which is fine.

# Generic key=value fragment (syslog-like or custom).
KV_RE = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"[^"]*"|\S+)')

# A leading syslog timestamp, e.g. "Oct 10 13:55:36".
SYSLOG_TIME_RE = re.compile(r'^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})')

# A leading ISO-ish timestamp, e.g. "2024-01-02T13:55:36" or "2024-01-02 13:55:36".
ISO_TIME_RE = re.compile(r'^(?P<iso>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})')

# The standard /var/log/auth.log style: "Jan  2 13:55:36 host sshd[123]: message".
AUTH_LOG_RE = re.compile(
    r'^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>[^:]+):(?P<message>.*)$'
)

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "TRACE", "CONNECT"}


@dataclass
class LogRecord:
    """A normalized, parser-independent log record."""

    raw: str
    ts: datetime | None = None
    source: str | None = None          # remote IP / host
    user: str | None = None
    method: str | None = None          # HTTP method, if any
    path: str | None = None            # request path
    status: int | None = None
    size: int | None = None
    service: str | None = None         # syslog service name, if any
    message: str | None = None         # syslog message body, if any
    extra: dict[str, Any] = field(default_factory=dict)


class ParseError(ValueError):
    """Raised by :func:`parse_line` when a line cannot be understood."""


_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_combined(line: str) -> LogRecord | None:
    m = COMBINED_RE.match(line)
    if not m:
        return None
    ts = _parse_apache_time(m.group("time"))
    size_raw = m.group("size")
    size = None if size_raw == "-" else _to_int(size_raw)
    return LogRecord(
        raw=line,
        ts=ts,
        source=m.group("host"),
        user=None if m.group("user") == "-" else m.group("user"),
        method=None,
        path=None,
        status=_to_int(m.group("status")),
        size=size,
    )


def _parse_apache_time(raw: str) -> datetime | None:
    # "10/Oct/2000:13:55:36 -0700"
    try:
        return datetime.strptime(raw.split(" ", 1)[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def _split_request(request: str) -> tuple[str | None, str | None]:
    parts = request.split(" ")
    method = parts[0] if parts and parts[0] in HTTP_METHODS else None
    path = parts[1] if len(parts) > 1 else None
    return method, path


def _parse_auth(line: str) -> LogRecord | None:
    m = AUTH_LOG_RE.match(line)
    if not m:
        return None
    mon = _MONTHS.get(m.group("mon"))
    ts = None
    if mon is not None:
        try:
            ts = datetime(2000, mon, int(m.group("day")), *map(int, m.group("time").split(":")))
        except ValueError:
            ts = None
    return LogRecord(
        raw=line,
        ts=ts,
        source=None,
        user=None,
        service=m.group("service"),
        message=m.group("message").strip(),
    )


def _parse_kv(line: str) -> LogRecord | None:
    kv = dict(KV_RE.findall(line))
    if not kv:
        return None
    # Keep key=value pairs that look like signal data rather than prose.
    interesting = any(k.lower() in {"ip", "src", "src_ip", "user", "username", "ssh", "service"}
                      for k in kv)
    if not interesting:
        return None
    kv = {k: v.strip('"') for k, v in kv.items()}
    ts = _extract_iso_time(line)
    return LogRecord(
        raw=line,
        ts=ts,
        source=kv.get("ip") or kv.get("src") or kv.get("src_ip"),
        user=kv.get("user") or kv.get("username"),
        service=kv.get("service"),
        message=line,
        extra=kv,
    )


def _extract_iso_time(line: str) -> datetime | None:
    m = ISO_TIME_RE.match(line)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group("iso").replace(" ", "T", 1))
    except ValueError:
        return None


def _to_int(value: str | int) -> int | None:
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def parse_line(line: str) -> LogRecord:
    """Parse one log line into a :class:`LogRecord`.

    Raises :class:`ParseError` when the line cannot be recognized as any
    supported format.
    """
    line = line.rstrip("\n")
    if not line.strip():
        raise ParseError("empty line")

    # Auth/syslog first because it is the most specific.
    rec = _parse_auth(line)
    if rec is not None:
        return rec

    rec = _parse_combined(line)
    if rec is not None:
        # Combined log: split the request line into method + path.
        request = COMBINED_RE.match(line).group("request")  # type: ignore[union-attr]
        rec.method, rec.path = _split_request(request)
        if rec.path:
            # Also surface any query string for the detector.
            rec.extra["query"] = rec.path.split("?", 1)[1] if "?" in rec.path else ""
        return rec

    rec = _parse_kv(line)
    if rec is not None:
        return rec

    raise ParseError("unrecognized format")
