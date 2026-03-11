"""
Standard Format Parsers
=======================

Parsers for common log formats (custom, syslog, apache, generic).
"""

import re
import pandas as pd
from datetime import datetime
from typing import Iterator
from .base import BaseAnalyzer
from ..utils.patterns import CP


def analyze_custom(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse custom structured log format.
    
    Format: [timestamp] [level] [module] message
    Example: [2024-01-01 00:00:00] [ERROR] [api] Connection failed
    
    Args:
        lines: Iterator of log lines
        
    Returns:
        pd.DataFrame: Parsed logs with columns:
            - timestamp: datetime
            - level: str
            - module: str
            - message: str
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
                    "message": m.group(4)
                })
            except ValueError:
                continue
    
    return pd.DataFrame(data)


def analyze_syslog(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse syslog format.
    
    Format: Mon DD HH:MM:SS hostname service: message
    Example: Jan 15 10:30:45 server nginx: Connection timeout
    
    Args:
        lines: Iterator of log lines
        
    Returns:
        pd.DataFrame: Parsed logs with columns:
            - timestamp: str (original format)
            - level: str (always "INFO")
            - module: str (service name)
            - message: str
            - ip: str (hostname)
    """
    pattern = re.compile(
        r"^(\w{3} +\d+ \d{2}:\d{2}:\d{2}) (\S+) (.+?): (.*)"
    )
    data = []
    
    for line in lines:
        if m := pattern.match(line):
            data.append({
                "timestamp": m.group(1),
                "level": "INFO",
                "module": m.group(3),
                "message": m.group(4),
                "ip": m.group(2)
            })
    
    return pd.DataFrame(data)


def analyze_apache(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse Apache Combined Log Format.
    
    Format: IP - - [timestamp] "METHOD path PROTOCOL" status size "referer" "user-agent"
    
    Args:
        lines: Iterator of log lines
        
    Returns:
        pd.DataFrame: Parsed logs with columns:
            - timestamp: str
            - level: str (status code)
            - module: str (IP address)
            - message: str (full request)
            - ip: str
            - status_code: str
            - user_agent: str
            - request_type: str (HTTP method)
            - request_path: str
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
    Parse generic/unknown format logs.
    
    Attempts to extract common elements using heuristics:
    - Timestamp patterns
    - Log level keywords
    - IP addresses
    
    Args:
        lines: Iterator of log lines
        
    Returns:
        pd.DataFrame: Parsed logs with columns:
            - timestamp: str or None
            - level: str ("UNKNOWN" if not found)
            - module: str (always "unknown")
            - message: str (full line)
            - ip: str or None
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
            "ip": ip_match.group(1) if ip_match else None
        })
    
    return pd.DataFrame(data)


__all__ = [
    "analyze_custom",
    "analyze_syslog",
    "analyze_apache",
    "analyze_generic",
]
