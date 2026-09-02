"""
Unit tests for the Log Analyzer.

These tests exercise the parser, the detector heuristics and the reporter
without touching the CLI or the network.
"""

from analyzer.detector import Detector, DetectorConfig
from analyzer.parser import LogRecord, parse_line, ParseError
from analyzer.reporter import build_summary

import pytest


# --- Parsing ---------------------------------------------------------------
def test_parse_combined_http():
    line = '127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326'
    rec = parse_line(line)
    assert rec.source == "127.0.0.1"
    assert rec.user == "frank"
    assert rec.path == "/index.html"
    assert rec.status == 200
    assert rec.size == 2326


def test_parse_auth_failure():
    line = "Jan  2 13:55:36 host sshd[2110]: Failed password for invalid user admin from 203.0.113.7 port 51024 ssh2"
    rec = parse_line(line)
    assert rec.service == "sshd"
    assert rec.source is None
    assert "Failed password" in (rec.message or "")


def test_parse_suspicious_query_extracted():
    line = '198.51.100.23 - - [10/Oct/2024:14:01:02 -0700] "GET /search?q=1 HTTP/1.1" 500 89'
    rec = parse_line(line)
    assert rec.path == "/search?q=1"
    assert rec.extra.get("query") == "q=1"


def test_parse_unknown_raises():
    with pytest.raises(ParseError):
        parse_line("this is not a log line at all")


# --- Detection -------------------------------------------------------------
def test_detect_sql_injection():
    rec = parse_line(
        '198.51.100.23 - - [10/Oct/2024:14:01:02 -0700] '
        '"GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 189'
    )
    det = Detector(DetectorConfig(scan_port_threshold=100, burst_min_requests=1000))
    det.add(rec)
    assert any(f.type == "sql-injection" for f in det.findings)


def test_detect_brute_force():
    config = DetectorConfig(max_failed_attempts=3, window_seconds=600)
    det = Detector(config)
    for i in range(4):
        rec = LogRecord(
            raw=f"Jan  2 13:5{i}:36 host sshd[{i}]: Failed password for user admin from 203.0.113.7 port {i} ssh2",
            service="sshd",
            message=f"Failed password for user admin from 203.0.113.7 port {i} ssh2",
        )
        det.add(rec)
    assert any(f.type == "brute-force" and f.count >= 4 for f in det.findings)


def test_detect_port_scan():
    det = Detector(DetectorConfig(scan_port_threshold=4))
    for port in ("/admin", "/login", "/api", "/wp-admin", "/robots.txt"):
        rec = LogRecord(raw=f"GET {port}", source="10.10.10.10", method="GET", path=port)
        det.add(rec)
    assert any(f.type == "port-scan" and f.count >= 4 for f in det.findings)


def test_detect_blacklist():
    config = DetectorConfig(blacklist={"185.220.101.34"})
    det = Detector(config)
    rec = LogRecord(raw="GET /account", source="185.220.101.34", method="GET", path="/account")
    det.add(rec)
    assert any(f.type == "blacklisted-ip" for f in det.findings)


# --- Reporter --------------------------------------------------------------
def test_summary_shape():
    config = DetectorConfig(blacklist={"1.2.3.4"})
    det = Detector(config)
    det.add(LogRecord(raw="GET /x", source="1.2.3.4", method="GET", path="/x"))
    summary = build_summary(det.findings)
    assert "total_findings" in summary
    assert summary["total_findings"] == 1
    assert summary["findings"][0]["type"] == "blacklisted-ip"
