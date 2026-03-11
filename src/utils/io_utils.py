"""
I/O Utilities
=============

Utilities for file handling, streaming, and format detection.
"""

from typing import Iterator, Tuple
from functools import lru_cache
from .patterns import CP


def iter_lines(uploaded_file, encoding: str = "utf-8", 
               errors: str = "ignore") -> Iterator[str]:
    """
    Memory-efficient line iteration from uploaded file.
    
    Args:
        uploaded_file: Streamlit UploadedFile object or file-like object
        encoding: Text encoding (default: utf-8)
        errors: Error handling strategy (default: ignore)
        
    Yields:
        str: Decoded line without trailing newline
        
    Example:
        >>> for line in iter_lines(uploaded_file):
        ...     process(line)
    """
    uploaded_file.seek(0)
    for bline in uploaded_file:
        try:
            yield bline.decode(encoding, errors=errors).rstrip("\n")
        except (UnicodeDecodeError, AttributeError):
            continue


def merge_multiline_stack(iterable: Iterator[str]) -> Iterator[str]:
    """
    Merge stack trace continuation lines into single entries.
    
    Identifies continuation lines based on:
    - Leading whitespace
    - Common stack trace keywords (at, Caused by:, Traceback, etc.)
    
    Args:
        iterable: Iterator of log lines
        
    Yields:
        str: Merged log entry (may contain newlines)
        
    Example:
        >>> lines = ["ERROR: Failed", "    at Module.fn()", "    at Main()"]
        >>> list(merge_multiline_stack(iter(lines)))
        ['ERROR: Failed\n    at Module.fn()\n    at Main()']
    """
    buf = []
    for raw in iterable:
        line = raw.rstrip("\n")
        
        if CP.TS_START.search(line):
            if buf:
                yield "\n".join(buf)
            buf = [line]
        elif CP.CONTINUATION.search(line):
            if buf:
                buf.append(line)
            else:
                buf = [line]
        else:
            if buf:
                buf.append(line)
            else:
                buf = [line]
    
    if buf:
        yield "\n".join(buf)


@lru_cache(maxsize=1)
def detect_format(sample_tuple: Tuple[str, ...]) -> str:
    """
    Detect log format from sample lines.
    
    Cached to avoid redundant detection on same samples.
    
    Args:
        sample_tuple: Tuple of sample log lines (for hashability)
        
    Returns:
        str: Detected format name or "generic"
        
    Supported Formats:
        - custom: Custom structured format
        - syslog: Standard syslog
        - apache: Apache access logs
        - json: Generic JSON logs
        - docker_json: Docker container logs
        - kubernetes_json: Kubernetes pod logs
        - cloudwatch_export: AWS CloudWatch
        - gcp_cloud_logging: GCP Cloud Logging
        - windows_event_xml: Windows Event Logs (XML)
        - generic: Unknown/mixed format
        
    Example:
        >>> lines = ["[2024-01-01 00:00:00] [INFO] [module] Message"]
        >>> detect_format(tuple(lines))
        'custom'
    """
    for fmt, pattern in CP.FORMAT_PATTERNS.items():
        for line in sample_tuple:
            if pattern.match(line.strip()):
                return fmt
    return "generic"


__all__ = [
    "iter_lines",
    "merge_multiline_stack",
    "detect_format",
]
