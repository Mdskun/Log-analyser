"""
Tests for src/utils: patterns (IPV4, PII), enrichment, io_utils.
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta

from src.utils.patterns import CP
from src.utils.enrichment import (
    detect_line_type,
    parse_user_agent,
    redact_pii,
    parse_response_time,
    add_enrichments,
)
from src.utils.io_utils import detect_format, merge_multiline_stack


# ============================================================
# IPV4 regex
# ============================================================

class TestIPV4Pattern:
    def test_matches_valid_ip(self):
        assert CP.IPV4.search("request from 192.168.1.1")

    def test_matches_boundary_values(self):
        assert CP.IPV4.search("0.0.0.0")
        assert CP.IPV4.search("255.255.255.255")

    def test_rejects_octet_above_255(self):
        assert not CP.IPV4.search("999.999.999.999")
        assert not CP.IPV4.search("256.0.0.1")
        assert not CP.IPV4.search("192.168.1.300")

    def test_does_not_match_lone_number(self):
        assert not CP.IPV4.search("12345")


# ============================================================
# PII patterns
# ============================================================

class TestPIIPatterns:
    def test_email_detected(self):
        assert CP.EMAIL.search("user@example.com")

    def test_email_no_false_positive(self):
        assert not CP.EMAIL.search("no-at-sign.here")

    def test_uuid_detected(self):
        assert CP.UUID.search("550e8400-e29b-41d4-a716-446655440000")

    def test_jwt_token_detected(self):
        token = (
            "eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiJ1c2VyIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert CP.TOKEN.search(token)


# ============================================================
# detect_line_type
# ============================================================

LINE_TYPE_CASES = [
    ("GET /api/users HTTP/1.1",         "HTTP_ACCESS"),
    ("Traceback (most recent call last):", "EXCEPTION"),
    ("SQLSTATE[42S02]: Table not found", "DB_ERROR"),
    ("Connection timed out after 30s",   "TIMEOUT"),
    ("unauthorized: invalid token",      "AUTH"),
    ("Connection refused ECONNREFUSED",  "NETWORK"),
    ("Out of memory: kill process",      "RESOURCE"),
    ("config file missing key: DB_URL",  "CONFIG"),
    ("service starting on port 8080",    "STARTUP_SHUTDOWN"),
    ("GC (Allocation Failure)",          "GC"),
    ("some normal log message",          "OTHER"),
]


class TestDetectLineType:
    @pytest.mark.parametrize("msg,expected", LINE_TYPE_CASES)
    def test_classification(self, msg, expected):
        assert detect_line_type(msg) == expected

    def test_non_string_returns_unknown(self):
        assert detect_line_type(123) == "UNKNOWN"


# ============================================================
# parse_user_agent
# ============================================================

class TestParseUserAgent:
    def test_chrome_windows_desktop(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit Chrome/91.0"
        browser, os_name, device = parse_user_agent(ua)
        assert browser == "Chrome"
        assert os_name == "Windows"
        assert device == "Desktop"

    def test_firefox_linux(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko Firefox/89.0"
        browser, os_name, device = parse_user_agent(ua)
        assert browser == "Firefox"
        assert os_name == "Linux"

    def test_empty_ua_returns_other(self):
        assert parse_user_agent("") == ("Other", "Other", "Other")

    def test_none_ua_returns_other(self):
        assert parse_user_agent(None) == ("Other", "Other", "Other")


# ============================================================
# redact_pii
# ============================================================

class TestRedactPii:
    def test_email_redacted(self):
        assert redact_pii("contact user@example.com now") == "contact <email> now"

    def test_ip_redacted(self):
        assert redact_pii("request from 192.168.1.1 failed") == "request from <ip> failed"

    def test_uuid_redacted(self):
        text = "id=550e8400-e29b-41d4-a716-446655440000"
        assert "<uuid>" in redact_pii(text)

    def test_non_string_passthrough(self):
        assert redact_pii(None) is None
        assert redact_pii(42) == 42

    def test_clean_text_unchanged(self):
        text = "no sensitive data here"
        assert redact_pii(text) == text

    def test_multiple_pii_redacted(self):
        text = "user@example.com logged in from 10.0.0.1"
        result = redact_pii(text)
        assert "<email>" in result
        assert "<ip>" in result


# ============================================================
# parse_response_time
# ============================================================

class TestParseResponseTime:
    def test_ms_unit(self):
        assert parse_response_time("latency=250ms") == 250.0

    def test_seconds_converted_to_ms(self):
        assert abs(parse_response_time("response_time=1.5s") - 1500.0) < 0.01

    def test_sec_unit(self):
        assert abs(parse_response_time("duration=2sec") - 2000.0) < 0.01

    def test_bare_number(self):
        assert parse_response_time("time: 300") == 300.0

    def test_no_timing_returns_none(self):
        assert parse_response_time("no timing here") is None

    def test_none_input_returns_none(self):
        assert parse_response_time(None) is None

    def test_non_string_returns_none(self):
        assert parse_response_time(42) is None


# ============================================================
# add_enrichments
# ============================================================

class TestAddEnrichments:
    def _base_df(self):
        return pd.DataFrame([
            {
                "timestamp": datetime(2024, 1, 15, 10, 0),
                "level": "ERROR",
                "module": "api",
                "message": "GET /health HTTP/1.1 200 latency=50ms user_id=abc123",
                "ip": None,
            },
            {
                "timestamp": datetime(2024, 1, 15, 10, 1),
                "level": "INFO",
                "module": "db",
                "message": "query executed successfully",
                "ip": "10.0.0.1",
            },
        ])

    def test_adds_line_type(self):
        result = add_enrichments(self._base_df())
        assert "line_type" in result.columns

    def test_adds_request_type(self):
        result = add_enrichments(self._base_df())
        assert result.iloc[0]["request_type"] == "GET"

    def test_adds_response_time(self):
        result = add_enrichments(self._base_df())
        assert result.iloc[0]["response_time_ms"] == 50.0

    def test_adds_user_id(self):
        result = add_enrichments(self._base_df())
        assert result.iloc[0]["user_id"] == "abc123"

    def test_ip_fallback_from_message(self):
        df = pd.DataFrame([{
            "timestamp": datetime(2024, 1, 15, 10, 0),
            "level": "INFO",
            "module": "app",
            "message": "request from 192.168.1.50 received",
        }])
        result = add_enrichments(df)
        assert result.iloc[0]["ip"] == "192.168.1.50"

    def test_empty_df_unchanged(self):
        result = add_enrichments(pd.DataFrame())
        assert result.empty


# ============================================================
# detect_format
# ============================================================

FORMAT_CASES = [
    ("[2024-01-15 10:00:00] [INFO] [api] message",                         "custom"),
    ("Jan 15 10:00:00 server nginx: message",                              "syslog"),
    ('127.0.0.1 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1', "apache"),
    ('{"level": "INFO", "message": "ok"}',                                 "json"),
]


class TestDetectFormat:
    @pytest.mark.parametrize("line,expected_fmt", FORMAT_CASES)
    def test_format_detected(self, line, expected_fmt):
        assert detect_format(tuple([line])) == expected_fmt

    def test_unknown_falls_back_to_generic(self):
        assert detect_format(tuple(["this is a mystery log line"])) == "generic"


# ============================================================
# merge_multiline_stack
# ============================================================

class TestMergeMultilineStack:
    def test_merges_stack_trace(self):
        lines = [
            "2024-01-15 10:00:00 ERROR db failed",
            "    at Module.connect(db.js:42)",
            "    at Server.start(app.js:10)",
            "2024-01-15 10:01:00 INFO all good",
        ]
        result = list(merge_multiline_stack(iter(lines)))
        assert len(result) == 2
        assert "at Module.connect" in result[0]

    def test_single_line_passthrough(self):
        lines = ["2024-01-15 10:00:00 INFO single line"]
        result = list(merge_multiline_stack(iter(lines)))
        assert len(result) == 1

    def test_empty_input(self):
        result = list(merge_multiline_stack(iter([])))
        assert result == []
