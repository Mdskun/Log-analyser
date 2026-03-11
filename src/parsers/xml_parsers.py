"""
XML Format Parsers
==================

Parsers for XML-based log formats (Windows Event Logs).
"""

import re
import pandas as pd
from typing import Iterator


def analyze_windows_event_xml(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse Windows EventLog XML exports.
    
    Note: This is a lightweight parser for XML exports.
    Binary .evtx files require additional dependencies (python-evtx).
    
    Args:
        lines: Iterator of XML log lines
        
    Returns:
        pd.DataFrame: Parsed logs with columns:
            - timestamp: str
            - level: str (numeric level)
            - module: str (provider name)
            - message: str (data content)
            - ip: None
    """
    rows = []
    buf = []
    
    def flush_event(event_text: str):
        """Extract fields from complete event XML."""
        if not event_text:
            return
        
        # Use regex for lightweight extraction (avoids XML parser dependency)
        ts = re.search(
            r"<TimeCreated[^>]*SystemTime=\"([^\"]+)\"", 
            event_text
        )
        level = re.search(r"<Level>(\d+)</Level>", event_text)
        provider = re.search(
            r"<Provider[^>]*Name=\"([^\"]+)\"", 
            event_text
        )
        msg = re.search(r"<Data>(.*?)</Data>", event_text, re.DOTALL)
        
        rows.append({
            "timestamp": ts.group(1) if ts else None,
            "level": level.group(1) if level else "INFO",
            "module": provider.group(1) if provider else "WindowsEvent",
            "message": (
                msg.group(1).strip().replace("\n", " ") if msg else ""
            ),
            "ip": None
        })
    
    # Accumulate lines into complete event blocks
    for line in lines:
        if "<Event" in line:
            buf = [line]
        elif "</Event>" in line:
            buf.append(line)
            flush_event("\n".join(buf))
            buf = []
        elif buf:
            buf.append(line)
    
    return pd.DataFrame(rows)


__all__ = ["analyze_windows_event_xml"]
