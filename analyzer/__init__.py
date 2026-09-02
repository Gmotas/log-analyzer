"""
analyzer — detection engine for the Log Analyzer security tool.

This package implements the full analysis pipeline used by the
``log_analyzer.py`` CLI:

* :mod:`analyzer.parser`   — tolerant, format-aware log line parsing
* :mod:`analyzer.detector` — heuristic-based suspicious-activity detection
* :mod:`analyzer.reporter` — human-readable and machine-readable reporting

All modules use only the Python standard library so the tool can run in
any modern Python 3 environment without third-party dependencies.
"""

__version__ = "1.0.0"
