"""
Shared pytest fixtures for Log Analyzer Pro tests.
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Sample log lines
# ---------------------------------------------------------------------------

CUSTOM_LINES = [
    "[2024-01-15 10:00:00] [INFO] [api] Service started",
    "[2024-01-15 10:01:00] [ERROR] [db] Connection failed",
    "[2024-01-15 10:02:00] [WARNING] [cache] Cache miss",
    "[2024-01-15 10:03:00] [DEBUG] [api] Processing request",
    "not a valid custom line",
]

SYSLOG_LINES = [
    "Jan 15 10:00:00 webserver nginx: error opening /etc/nginx/conf",
    "Jan 15 10:01:00 appserver app: info service running normally",
    "Jan 15 10:02:00 dbserver mysql: warning too many connections",
    "Jan 15 10:03:00 host kernel: debug page fault at 0x0",
    "not a syslog line",
]

APACHE_LINES = [
    '127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.1 - - [15/Jan/2024:10:01:00 +0000] "POST /api/login HTTP/1.1" 401 56 "-" "curl/7.68"',
    '192.168.1.1 - - [15/Jan/2024:10:02:00 +0000] "GET /static/app.js HTTP/1.1" 304 0 "-" "Chrome/91"',
    "not an apache line",
]

JSON_LINES = [
    '{"timestamp": "2024-01-15T10:00:00Z", "level": "INFO", "message": "started", "module": "api"}',
    '{"timestamp": "2024-01-15T10:01:00Z", "level": "ERROR", "message": "db timeout", "module": "db"}',
    'not json',
    '{"broken": }',
]

GENERIC_LINES = [
    "2024-01-15 10:00:00 INFO Something happened",
    "2024-01-15 10:01:00 ERROR Something broke",
    "10:02:00 DEBUG no date prefix",
    "plain log line with no structure",
]


# ---------------------------------------------------------------------------
# DataFrame fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_df():
    """Small enriched DataFrame for analytics tests."""
    now = datetime(2024, 1, 15, 10, 0, 0)
    rows = []
    levels = ["INFO", "ERROR", "WARNING", "ERROR", "INFO", "ERROR", "DEBUG"]
    modules = ["api", "db", "api", "db", "cache", "api", "db"]

    for i, (lvl, mod) in enumerate(zip(levels, modules)):
        rows.append({
            "timestamp": now + timedelta(minutes=i * 10),
            "level": lvl,
            "module": mod,
            "message": f"{lvl.lower()} event from {mod} number {i}",
            "ip": f"10.0.0.{i + 1}",
        })

    return pd.DataFrame(rows)


@pytest.fixture
def empty_df():
    return pd.DataFrame()
