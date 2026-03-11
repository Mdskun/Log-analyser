"""
Utils Package
=============

Utilities for pattern matching, enrichment, and I/O operations.
"""

from .patterns import CP, CompiledPatterns
from .enrichment import (
    detect_line_type,
    parse_user_agent,
    redact_pii,
    parse_response_time,
    add_enrichments,
)
from .io_utils import (
    iter_lines,
    merge_multiline_stack,
    detect_format,
)

__all__ = [
    # Patterns
    "CP",
    "CompiledPatterns",
    # Enrichment
    "detect_line_type",
    "parse_user_agent",
    "redact_pii",
    "parse_response_time",
    "add_enrichments",
    # I/O
    "iter_lines",
    "merge_multiline_stack",
    "detect_format",
]
