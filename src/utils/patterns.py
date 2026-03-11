"""
Regex Pattern Definitions
=========================

Centralized, pre-compiled regex patterns for optimal performance.
All patterns are compiled once at module import time.

Usage:
    from src.utils.patterns import CP
    if CP.HTTP_METHOD.search(line):
        # process HTTP log
"""

import re
from typing import List, Tuple


class CompiledPatterns:
    """Centralized repository of pre-compiled regex patterns."""

    # ==================== Format Detection ====================
    FORMAT_PATTERNS = {
        "custom": re.compile(
            r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[\w+\] \[.*?\] .*"
        ),
        "syslog": re.compile(
            r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} .+"
        ),
        "apache": re.compile(
            r"\d+\.\d+\.\d+\.\d+ - - \[.*?\] \".*?\" \d{3} \d+"
        ),
        "json": re.compile(r"^\{.*\}$"),
        "docker_json": re.compile(r"^\{.*\"log\":.*\"time\":.*\}$"),
        "kubernetes_json": re.compile(r"^\{.*\"kubernetes\"\s*:\s*\{.*\}.*\}$"),
        "cloudwatch_export": re.compile(
            r"^\{.*\"logGroup\".*\"logStream\".*\"message\".*\}$"
        ),
        "gcp_cloud_logging": re.compile(
            r"^\{.*(\"textPayload\"|\"jsonPayload\"|\"protoPayload\").*\}$"
        ),
        "windows_event_xml": re.compile(r"^\s*<Event[ >].*"),
    }

    # ==================== Multiline Handling ====================
    TS_START = re.compile(
        r"^(\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|"
        r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
        r"\d+\.\d+\.\d+\.\d+ - - \[|<Event|\{)"
    )

    CONTINUATION = re.compile(
        r"^(\s+|at\s|\.\.\.|Caused by:|Traceback|File \".+\", line \d+)"
    )

    # ==================== Line Type Detection ====================
    LINE_TYPES: List[Tuple[str, re.Pattern]] = [
        ("HTTP_ACCESS", re.compile(
            r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b .* HTTP/\d", re.I
        )),
        ("EXCEPTION", re.compile(
            r"Traceback|Exception:|Error:|Caused by:|\bat\s+\w+\.", re.I
        )),
        ("DB_ERROR", re.compile(
            r"SQLSTATE|ORA-\d+|psql:|Sequelize|MongoError|jdbc|Deadlock", re.I
        )),
        ("TIMEOUT", re.compile(
            r"timed? out|timeout|deadline exceeded", re.I
        )),
        ("AUTH", re.compile(
            r"unauthorized|forbidden|invalid token|auth|login failed", re.I
        )),
        ("NETWORK", re.compile(
            r"connection (reset|refused|closed)|ECONN|socket|TLS|SSL", re.I
        )),
        ("RESOURCE", re.compile(
            r"out of memory|OOM|disk\s(full|quota)|cpu (throttle|limit)", re.I
        )),
        ("CONFIG", re.compile(
            r"config|configuration|env var|missing key", re.I
        )),
        ("STARTUP_SHUTDOWN", re.compile(
            r"(service|server) (starting|started|stopping|stopped)", re.I
        )),
        ("GC", re.compile(
            r"GC \(|Garbage Collector|Allocation Failure", re.I
        )),
    ]

    # ==================== HTTP Extraction ====================
    HTTP_PATH = re.compile(
        r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\"]+)"
    )

    HTTP_STATUS = re.compile(r"\s(\d{3})(?:\s|$)")

    HTTP_METHOD = re.compile(
        r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"
    )

    # ==================== Apache Combined Format ====================
    APACHE_COMBINED = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
        r'"(?P<req>[A-Z]+ [^\s]+ [^"]+)" (?P<status>\d{3}) '
        r'(?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
    )

    # ==================== PII Detection ====================
    EMAIL = re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    )

    # Validates each octet is 0-255 so "999.999.999.999" no longer matches.
    IPV4 = re.compile(
        r"\b"
        r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
        r"\b"
    )

    UUID = re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    )

    TOKEN = re.compile(
        r"\b(?:eyJ[\w-]+\.[\w-]+\.[\w-]+|"
        r"AKIA[0-9A-Z]{16}|"
        r"AIza[0-9A-Za-z-_]{35})\b"
    )

    USER_ID = re.compile(
        r"user[_-]?id\s*[:=]\s*([A-Za-z0-9_-]+)", re.I
    )

    RESPONSE_TIME = re.compile(
        r"(?:latency|response[_-]?time|request[_-]?time|duration|time)"
        r"\s*[:=]\s*([0-9]*\.?[0-9]+)\s*(ms|s|sec|seconds)?",
        re.I,
    )

    # ==================== User Agent Parsing ====================
    UA_BROWSERS: List[Tuple[str, re.Pattern]] = [
        ("Chrome",  re.compile(r"Chrome\/[0-9]+", re.I)),
        ("Firefox", re.compile(r"Firefox\/[0-9]+", re.I)),
        ("Safari",  re.compile(r"Version\/[0-9].*Safari", re.I)),
        ("Edge",    re.compile(r"Edg\/[0-9]+", re.I)),
        ("IE",      re.compile(r"MSIE|Trident", re.I)),
    ]

    UA_OS: List[Tuple[str, re.Pattern]] = [
        ("Windows", re.compile(r"Windows NT", re.I)),
        ("macOS",   re.compile(r"Mac OS X", re.I)),
        ("Linux",   re.compile(r"Linux", re.I)),
        ("Android", re.compile(r"Android", re.I)),
        ("iOS",     re.compile(r"iPhone|iPad", re.I)),
    ]

    UA_DEVICE: List[Tuple[str, re.Pattern]] = [
        ("Mobile",  re.compile(r"Mobile|Android|iPhone|iPad", re.I)),
        ("Desktop", re.compile(r"Windows NT|Mac OS X|X11; Linux", re.I)),
    ]

    # ==================== Generic Patterns ====================
    TIMESTAMP = re.compile(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2})"
    )

    LOG_LEVEL = re.compile(
        r"\b(INFO|ERROR|WARN|WARNING|DEBUG|CRITICAL)\b", re.IGNORECASE
    )


# Singleton instance for global use
CP = CompiledPatterns()

__all__ = ["CP", "CompiledPatterns"]
