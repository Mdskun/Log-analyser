"""
Apache mod_jk / Tomcat Connector Format Parsers
===============================================

Parsers for Apache mod_jk logs and related Tomcat connector formats.

Common mod_jk log format:
    [Sun Dec 04 04:51:14 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties
    [Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6
    [Sun Dec 04 04:51:37 2005] [notice] jk2_init() Found child 6736 in scoreboard slot 10

This parser handles:
- Apache error log timestamps (Mon/Tue/... with date format)
- mod_jk specific severity levels (notice, error, warn, crit, etc)
- Worker initialization messages
- Child process tracking
- Configuration file references
"""

import re
import pandas as pd
from datetime import datetime
from typing import Iterator, Optional, Dict, Any
from .base import BaseAnalyzer
from ..utils.patterns import CP


class ModJKParser(BaseAnalyzer):
    """
    Parser for Apache mod_jk/Tomcat connector logs.
    
    Supports flexible timestamp parsing and custom format templates.
    """
    
    # mod_jk severity level mapping
    SEVERITY_MAP = {
        "emerg": "CRITICAL",
        "alert": "CRITICAL", 
        "crit": "CRITICAL",
        "critical": "CRITICAL",
        "error": "ERROR",
        "warn": "WARNING",
        "warning": "WARNING",
        "notice": "INFO",
        "info": "INFO",
        "debug": "DEBUG",
    }
    
    # Timestamp pattern: [Day Month DD HH:MM:SS YYYY]
    TIMESTAMP_PATTERN = re.compile(
        r"\[(\w{3}\s+\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\]"
    )
    
    # Alternative compact timestamp: [YYYY-MM-DD HH:MM:SS]
    TIMESTAMP_COMPACT = re.compile(
        r"\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]"
    )
    
    # Severity level
    SEVERITY_PATTERN = re.compile(
        r"\[(\w+)\]",
        re.IGNORECASE
    )
    
    # Composite pattern for full line parsing
    MODJK_PATTERN = re.compile(
        r"^\[([^\]]+)\]\s+\[(\w+)\]\s+(.*?)(?:\s+(.+))?$",
        re.IGNORECASE
    )
    
    def __init__(self, format_config: Optional[Dict[str, str]] = None):
        """
        Initialize mod_jk parser with optional custom format config.
        
        Args:
            format_config: Custom format configuration dict with keys:
                - 'timestamp_format': strftime format string (default: auto-detect)
                - 'severity_key': which bracket group contains severity (default: auto)
                - 'message_key': which part contains main message (default: auto)
        """
        super().__init__()
        self.format_config = format_config or {}
    
    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """
        Parse timestamp with multiple format support.
        
        Handles:
        - Apache format: "Day Month DD HH:MM:SS YYYY" e.g., "Sun Dec 04 04:51:14 2005"
        - Compact format: "YYYY-MM-DD HH:MM:SS"
        """
        if not ts_str:
            return None
        
        # Custom format from config
        custom_fmt = self.format_config.get('timestamp_format')
        if custom_fmt:
            try:
                return datetime.strptime(ts_str.strip(), custom_fmt)
            except ValueError:
                pass
        
        # Try Apache format
        try:
            return datetime.strptime(ts_str.strip(), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            pass
        
        # Try ISO/compact format
        try:
            return datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        
        # Try other common formats
        formats = [
            "%b %d %H:%M:%S %Y",  # Dec 04 04:51:14 2005
            "%d/%b/%Y:%H:%M:%S",  # Apache alt format
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        
        return None
    
    def extract_worker_info(self, message: str) -> Dict[str, Any]:
        """Extract mod_jk specific information from message."""
        info = {}
        
        # Worker environment state
        if "workerEnv" in message:
            info["worker_type"] = "environment"
            if "error state" in message:
                state_match = re.search(r"error state (\d+)", message)
                if state_match:
                    info["error_state"] = state_match.group(1)
        
        # Child process tracking
        if "Found child" in message:
            info["worker_type"] = "child_process"
            child_match = re.search(r"Found child (\d+)", message)
            slot_match = re.search(r"slot (\d+)", message)
            if child_match:
                info["child_pid"] = child_match.group(1)
            if slot_match:
                info["slot"] = slot_match.group(1)
        
        # Configuration file
        if ".properties" in message:
            props_match = re.search(r"(/[^\s]+\.properties)", message)
            if props_match:
                info["config_file"] = props_match.group(1)
        
        return info


def analyze_apache_modjk(lines: Iterator[str], 
                         format_config: Optional[Dict[str, str]] = None) -> pd.DataFrame:
    """
    Parse Apache mod_jk log format.
    
    Format: [timestamp] [severity] message
    
    Args:
        lines: Iterator of log lines
        format_config: Optional custom format configuration
        
    Returns:
        DataFrame with parsed mod_jk logs
        
    Example:
        >>> lines = iter([
        ...     "[Sun Dec 04 04:51:14 2005] [error] mod_jk child workerEnv in error state 6",
        ... ])
        >>> df = analyze_apache_modjk(lines)
    """
    parser = ModJKParser(format_config)
    data = []
    
    for line in lines:
        if not line.strip():
            continue
        
        match = parser.MODJK_PATTERN.match(line)
        if not match:
            # Try to parse any line with timestamp + severity pattern
            ts_match = parser.TIMESTAMP_PATTERN.search(line)
            if not ts_match:
                ts_match = parser.TIMESTAMP_COMPACT.search(line)
            
            if ts_match:
                sev_match = parser.SEVERITY_PATTERN.search(line)
                severity = sev_match.group(1).lower() if sev_match else "notice"
                message = line
                timestamp_str = ts_match.group(1)
            else:
                continue
        else:
            timestamp_str = match.group(1)
            severity = match.group(2).lower()
            message = match.group(3) if match.group(3) else ""
            extra = match.group(4) if match.group(4) else ""
            if extra:
                message += f" {extra}"
        
        # Parse timestamp
        timestamp = parser.parse_timestamp(timestamp_str)
        if not timestamp:
            continue
        
        # Map severity
        level = parser.SEVERITY_MAP.get(severity, severity.upper())
        
        # Extract worker info
        worker_info = parser.extract_worker_info(message)
        
        record = {
            "timestamp": timestamp,
            "level": level,
            "severity": severity,
            "module": "mod_jk",
            "message": message.strip(),
        }
        
        # Add worker-specific fields
        record.update(worker_info)
        
        data.append(record)
    
    return pd.DataFrame(data)


def analyze_tomcat_connector(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse Tomcat Connector logs (similar format to mod_jk).
    
    These often appear in catalina.out or similar Tomcat logs.
    """
    data = []
    
    for line in lines:
        if not line.strip():
            continue
        
        # Tomcat often uses: YYYY-MM-DD HH:MM:SS.mmm [severity] message
        pattern = re.match(
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.,]\d{3})\s+(\[[\w\s]+\])\s+(.*)",
            line
        )
        
        if pattern:
            try:
                ts = datetime.strptime(pattern.group(1)[:19], "%Y-%m-%d %H:%M:%S")
                severity = pattern.group(2).strip("[]").lower()
                level = ModJKParser.SEVERITY_MAP.get(severity, severity.upper())
                message = pattern.group(3)
                
                data.append({
                    "timestamp": ts,
                    "level": level,
                    "severity": severity,
                    "module": "tomcat_connector",
                    "message": message,
                })
            except (ValueError, AttributeError):
                continue
    
    return pd.DataFrame(data)


__all__ = [
    "analyze_apache_modjk",
    "analyze_tomcat_connector",
    "ModJKParser",
]
