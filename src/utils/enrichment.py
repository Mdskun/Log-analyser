"""
Data Enrichment Utilities
==========================

Functions for extracting metadata and enriching log data.
"""

import pandas as pd
from typing import Optional, Tuple
from functools import lru_cache
from .patterns import CP


@lru_cache(maxsize=10000)
def detect_line_type(msg: str) -> str:
    """
    Classify log line type based on content patterns.
    
    Cached for performance on repeated messages.
    
    Args:
        msg: Log message text
        
    Returns:
        str: Line type classification
        
    Types:
        - HTTP_ACCESS: HTTP request logs
        - EXCEPTION: Exception/error traces
        - DB_ERROR: Database errors
        - TIMEOUT: Timeout events
        - AUTH: Authentication/authorization
        - NETWORK: Network connectivity
        - RESOURCE: Resource exhaustion
        - CONFIG: Configuration issues
        - STARTUP_SHUTDOWN: Service lifecycle
        - GC: Garbage collection
        - OTHER: Unclassified
        - UNKNOWN: Invalid input
    """
    if not isinstance(msg, str):
        return "UNKNOWN"
    
    for type_name, pattern in CP.LINE_TYPES:
        if pattern.search(msg):
            return type_name
    
    return "OTHER"


@lru_cache(maxsize=5000)
def parse_user_agent(ua: str) -> Tuple[str, str, str]:
    """
    Parse user agent string into browser, OS, and device type.
    
    Cached for performance on repeated user agents.
    
    Args:
        ua: User agent string
        
    Returns:
        Tuple[str, str, str]: (browser, os, device)
        
    Example:
        >>> parse_user_agent("Mozilla/5.0 (Windows NT 10.0) Chrome/91.0")
        ('Chrome', 'Windows', 'Desktop')
    """
    if not isinstance(ua, str) or not ua:
        return "Other", "Other", "Other"
    
    browser = next(
        (name for name, rx in CP.UA_BROWSERS if rx.search(ua)), 
        "Other"
    )
    os_name = next(
        (name for name, rx in CP.UA_OS if rx.search(ua)), 
        "Other"
    )
    device = next(
        (name for name, rx in CP.UA_DEVICE if rx.search(ua)), 
        "Other"
    )
    
    return browser, os_name, device


def redact_pii(text: str) -> str:
    """
    Redact personally identifiable information from text.
    
    Replaces:
        - Email addresses → <email>
        - IP addresses → <ip>
        - UUIDs → <uuid>
        - Auth tokens → <token>
    
    Args:
        text: Text potentially containing PII
        
    Returns:
        str: Text with PII redacted
        
    Example:
        >>> redact_pii("user@example.com logged in from 192.168.1.1")
        '<email> logged in from <ip>'
    """
    if not isinstance(text, str):
        return text
    
    text = CP.EMAIL.sub("<email>", text)
    text = CP.IPV4.sub("<ip>", text)
    text = CP.UUID.sub("<uuid>", text)
    text = CP.TOKEN.sub("<token>", text)
    
    return text


def parse_response_time(text: str) -> Optional[float]:
    """
    Extract response time from log message.
    
    Handles various formats and units (ms, s, sec, seconds).
    Normalizes all values to milliseconds.
    
    Args:
        text: Log message text
        
    Returns:
        Optional[float]: Response time in milliseconds, or None
        
    Example:
        >>> parse_response_time("Request completed in 1.5s")
        1500.0
        >>> parse_response_time("latency=250ms")
        250.0
    """
    if not isinstance(text, str):
        return None
    
    if m := CP.RESPONSE_TIME.search(text):
        try:
            val = float(m.group(1))
            unit = (m.group(2) or "ms").lower()
            
            # Convert to milliseconds
            if unit in ["s", "sec", "seconds"]:
                return val * 1000.0
            return val
        except ValueError:
            return None
    
    return None


def add_enrichments(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add all enrichments to dataframe.
    
    Enrichments include:
        - Line type classification
        - HTTP method and path extraction
        - Status code extraction
        - Response time extraction
        - User ID extraction
        - User agent parsing
        - IP address fallback
    
    Args:
        df: Log dataframe with at least 'message' column
        
    Returns:
        pd.DataFrame: Enriched dataframe with additional columns
        
    New Columns:
        - line_type: Classification of log line
        - request_type: HTTP method (GET, POST, etc.)
        - request_path: HTTP path
        - status_code: HTTP status code
        - response_time_ms: Response time in milliseconds
        - user_id: Extracted user identifier
        - ua_browser: Browser name
        - ua_os: Operating system
        - ua_device: Device type
    """
    if df.empty:
        return df
    
    # Line type classification
    if "message" in df.columns:
        df["line_type"] = df["message"].apply(detect_line_type)
    
    # Extract metadata from messages
    if "message" in df.columns:
        msg_series = df["message"].astype(str)
        
        # HTTP metadata
        df["request_type"] = msg_series.str.extract(CP.HTTP_METHOD, expand=False)
        df["request_path"] = msg_series.str.extract(CP.HTTP_PATH, expand=False)
        
        # Response time
        df["response_time_ms"] = msg_series.apply(parse_response_time)
        
        # User ID
        df["user_id"] = msg_series.str.extract(CP.USER_ID, expand=False)
        
        # Status code (from level or message)
        if "level" in df.columns:
            level_status = df["level"].astype(str).str.extract(
                r"^(\d{3})$", expand=False
            )
            msg_status = msg_series.str.extract(CP.HTTP_STATUS, expand=False)
            df["status_code"] = level_status.fillna(msg_status)
        
        # IP fallback from message if not already present
        if "ip" not in df.columns or df["ip"].isna().all():
            df["ip"] = msg_series.str.extract(CP.IPV4, expand=False)
    
    # User agent parsing
    if "user_agent" in df.columns and df["user_agent"].notna().any():
        ua_parsed = df["user_agent"].apply(parse_user_agent)
        df["ua_browser"], df["ua_os"], df["ua_device"] = zip(*ua_parsed)
    
    return df


__all__ = [
    "detect_line_type",
    "parse_user_agent",
    "redact_pii",
    "parse_response_time",
    "add_enrichments",
]
