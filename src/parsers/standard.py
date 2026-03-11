"""
Standard Format Parsers
=======================

Parsers for common log formats: custom, syslog, apache, generic.
"""

import re
import pandas as pd
from datetime import datetime
from typing import Iterator
from .base import BaseAnalyzer
from ..utils.patterns import CP

# Syslog severity keywords → normalised level
_SYSLOG_LEVELS = re.compile(
    r"\b(emerg|alert|crit|critical|err|error|warn|warning|notice|info|debug)\b",
    re.IGNORECASE,
)
_SYSLOG_LEVEL_MAP = {
    "emerg": "CRITICAL", "alert": "CRITICAL", "crit": "CRITICAL",
    "critical": "CRITICAL", "err": "ERROR", "error": "ERROR",
    "warn": "WARNING", "warning": "WARNING", "notice": "INFO",
    "info": "INFO", "debug": "DEBUG",
}


def analyze_custom(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse custom structured log format.

    Format: [timestamp] [level] [module] message
    Example: [2024-01-01 00:00:00] [ERROR] [api] Connection failed
    """
    pattern = re.compile(r"\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)")
    fmt = "%Y-%m-%d %H:%M:%S"
    data = []

    for line in lines:
        if m := pattern.match(line):
            try:
                data.append({
                    "timestamp": datetime.strptime(m.group(1), fmt),
                    "level": m.group(2),
                    "module": m.group(3),
                    "message": m.group(4),
                })
            except ValueError:
                continue

    return pd.DataFrame(data)


def analyze_syslog(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse syslog format.

    Format: Mon DD HH:MM:SS hostname service[pid]: message
    Example: Jan 15 10:30:45 server nginx[1234]: error opening file

    Level is inferred from keywords in the message (emerg/alert/crit/err/warn/
    notice/info/debug).  Falls back to "INFO" when no keyword is found.
    """
    pattern = re.compile(
        r"^(\w{3} +\d+ \d{2}:\d{2}:\d{2}) (\S+) (.+?): (.*)"
    )
    data = []

    for line in lines:
        if m := pattern.match(line):
            message = m.group(4)
            # Try to derive severity from the message text
            level_match = _SYSLOG_LEVELS.search(message)
            level = (
                _SYSLOG_LEVEL_MAP[level_match.group(1).lower()]
                if level_match
                else "INFO"
            )
            data.append({
                "timestamp": m.group(1),
                "level": level,
                "module": m.group(3),
                "message": message,
                "ip": m.group(2),
            })

    return pd.DataFrame(data)


def analyze_apache(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse Apache Combined Log Format.

    Format: IP - - [timestamp] "METHOD path PROTOCOL" status size "ref" "ua"
    """
    data = []

    for line in lines:
        if m := CP.APACHE_COMBINED.match(line):
            d = m.groupdict()
            req_parts = d["req"].split(" ")
            data.append({
                "timestamp": d["ts"],
                "level": d["status"],
                "module": d["ip"],
                "message": d["req"],
                "ip": d["ip"],
                "status_code": d["status"],
                "user_agent": d["ua"],
                "request_type": req_parts[0] if req_parts else None,
                "request_path": req_parts[1] if len(req_parts) > 1 else None,
            })

    return pd.DataFrame(data)


def analyze_generic(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse generic / unknown format logs using heuristics.

    Attempts to extract: timestamp, log level, IP address.
    """
    data = []

    for line in lines:
        ts_match = CP.TIMESTAMP.search(line)
        level_match = CP.LOG_LEVEL.search(line)
        ip_match = CP.IPV4.search(line)

        data.append({
            "timestamp": ts_match.group(1) if ts_match else None,
            "level": level_match.group(1).upper() if level_match else "UNKNOWN",
            "module": "unknown",
            "message": line.strip(),
            "ip": ip_match.group(0) if ip_match else None,
        })

    return pd.DataFrame(data)


__all__ = ["analyze_custom", "analyze_syslog", "analyze_apache", "analyze_generic"]
