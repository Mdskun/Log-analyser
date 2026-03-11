"""
Tests for src/parsers — custom, syslog, apache, generic, json, xml parsers.
"""

import pytest
from conftest import (
    CUSTOM_LINES, SYSLOG_LINES, APACHE_LINES, JSON_LINES, GENERIC_LINES,
)
from src.parsers.standard import (
    analyze_custom, analyze_syslog, analyze_apache, analyze_generic,
)
from src.parsers.json_parsers import analyze_json
from src.parsers.xml_parsers import analyze_windows_event_xml
from src.parsers.factory import LogParser


# ============================================================
# Custom parser
# ============================================================

class TestAnalyzeCustom:
    def test_parses_valid_lines(self):
        df = analyze_custom(iter(CUSTOM_LINES))
        assert len(df) == 4          # 5th line is invalid

    def test_columns_present(self):
        df = analyze_custom(iter(CUSTOM_LINES))
        for col in ("timestamp", "level", "module", "message"):
            assert col in df.columns

    def test_correct_level(self):
        df = analyze_custom(iter(CUSTOM_LINES))
        assert df.iloc[0]["level"] == "INFO"
        assert df.iloc[1]["level"] == "ERROR"

    def test_correct_module(self):
        df = analyze_custom(iter(CUSTOM_LINES))
        assert df.iloc[0]["module"] == "api"
        assert df.iloc[1]["module"] == "db"

    def test_empty_input(self):
        df = analyze_custom(iter([]))
        assert df.empty

    def test_all_invalid_lines(self):
        df = analyze_custom(iter(["garbage", "more garbage"]))
        assert df.empty


# ============================================================
# Syslog parser
# ============================================================

class TestAnalyzeSyslog:
    def test_parses_valid_lines(self):
        df = analyze_syslog(iter(SYSLOG_LINES))
        assert len(df) == 4          # 5th line is invalid

    def test_level_inferred_from_message(self):
        df = analyze_syslog(iter(SYSLOG_LINES))
        # First line contains "error" → should become ERROR, not hardcoded INFO
        assert df.iloc[0]["level"] == "ERROR"
        assert df.iloc[1]["level"] == "INFO"
        assert df.iloc[2]["level"] == "WARNING"
        assert df.iloc[3]["level"] == "DEBUG"

    def test_hostname_in_ip_column(self):
        df = analyze_syslog(iter(SYSLOG_LINES))
        assert df.iloc[0]["ip"] == "webserver"

    def test_fallback_to_info_when_no_keyword(self):
        line = "Jan 15 10:00:00 host service: normal operation"
        df = analyze_syslog(iter([line]))
        assert df.iloc[0]["level"] == "INFO"


# ============================================================
# Apache parser
# ============================================================

class TestAnalyzeApache:
    def test_parses_valid_lines(self):
        df = analyze_apache(iter(APACHE_LINES))
        assert len(df) == 3          # 4th line is invalid

    def test_ip_extracted(self):
        df = analyze_apache(iter(APACHE_LINES))
        assert df.iloc[0]["ip"] == "127.0.0.1"
        assert df.iloc[1]["ip"] == "10.0.0.1"

    def test_status_code(self):
        df = analyze_apache(iter(APACHE_LINES))
        assert df.iloc[0]["status_code"] == "200"
        assert df.iloc[1]["status_code"] == "401"

    def test_http_method(self):
        df = analyze_apache(iter(APACHE_LINES))
        assert df.iloc[0]["request_type"] == "GET"
        assert df.iloc[1]["request_type"] == "POST"

    def test_request_path(self):
        df = analyze_apache(iter(APACHE_LINES))
        assert df.iloc[0]["request_path"] == "/index.html"

    def test_user_agent(self):
        df = analyze_apache(iter(APACHE_LINES))
        assert "Mozilla" in df.iloc[0]["user_agent"]


# ============================================================
# Generic parser
# ============================================================

class TestAnalyzeGeneric:
    def test_every_line_produces_a_row(self):
        df = analyze_generic(iter(GENERIC_LINES))
        assert len(df) == len(GENERIC_LINES)

    def test_level_extracted_where_present(self):
        df = analyze_generic(iter(GENERIC_LINES))
        assert df.iloc[0]["level"] == "INFO"
        assert df.iloc[1]["level"] == "ERROR"

    def test_unknown_level_for_plain_line(self):
        df = analyze_generic(iter(["plain log line with no structure"]))
        assert df.iloc[0]["level"] == "UNKNOWN"

    def test_timestamp_extracted(self):
        df = analyze_generic(iter(GENERIC_LINES))
        assert df.iloc[0]["timestamp"] == "2024-01-15 10:00:00"

    def test_message_is_stripped(self):
        df = analyze_generic(iter(["  padded line  "]))
        assert df.iloc[0]["message"] == "padded line"


# ============================================================
# JSON parser
# ============================================================

class TestAnalyzeJson:
    def test_parses_valid_json_lines(self):
        df = analyze_json(iter(JSON_LINES))
        assert len(df) == 2          # 3rd is not JSON, 4th is broken JSON

    def test_fields_extracted(self):
        df = analyze_json(iter(JSON_LINES))
        assert df.iloc[0]["level"] == "INFO"
        assert df.iloc[0]["message"] == "started"
        assert df.iloc[0]["module"] == "api"

    def test_empty_input(self):
        df = analyze_json(iter([]))
        assert df.empty


# ============================================================
# Windows Event XML parser
# ============================================================

class TestAnalyzeWindowsEventXml:
    XML_LINES = [
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
        '  <System>',
        '    <Provider Name="Microsoft-Windows-Security-Auditing"/>',
        '    <TimeCreated SystemTime="2024-01-15T10:00:00.000Z"/>',
        '    <Level>4</Level>',
        '  </System>',
        '  <EventData>',
        '    <Data>Account logon failure</Data>',
        '  </EventData>',
        '</Event>',
    ]

    def test_parses_event(self):
        df = analyze_windows_event_xml(iter(self.XML_LINES))
        assert len(df) == 1

    def test_provider_name_in_module(self):
        df = analyze_windows_event_xml(iter(self.XML_LINES))
        assert "Security-Auditing" in df.iloc[0]["module"]

    def test_timestamp_extracted(self):
        df = analyze_windows_event_xml(iter(self.XML_LINES))
        assert "2024-01-15" in df.iloc[0]["timestamp"]

    def test_message_extracted(self):
        df = analyze_windows_event_xml(iter(self.XML_LINES))
        assert "logon failure" in df.iloc[0]["message"]


# ============================================================
# Factory
# ============================================================

class TestLogParserFactory:
    def test_supported_formats_includes_all_parsers(self):
        formats = LogParser.get_supported_formats()
        for fmt in ("custom", "syslog", "apache", "json", "docker_json",
                    "kubernetes_json", "cloudwatch_export", "gcp_cloud_logging",
                    "windows_event_xml", "generic"):
            assert fmt in formats

    def test_unknown_format_falls_back_to_generic(self):
        lines = ["2024-01-15 10:00:00 INFO test message"]
        df = LogParser.parse(iter(lines), "nonexistent_format")
        assert not df.empty

    def test_register_custom_parser(self):
        import pandas as pd

        def my_parser(lines):
            return pd.DataFrame([{"message": line} for line in lines])

        LogParser.register_parser("my_custom", my_parser)
        df = LogParser.parse(iter(["hello"]), "my_custom")
        assert df.iloc[0]["message"] == "hello"

        # cleanup
        del LogParser.PARSERS["my_custom"]
