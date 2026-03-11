"""
Log Analyzer - Professional Log Analysis Tool
==============================================

A modular, high-performance log file analyzer supporting multiple formats
with comprehensive analytics and visualizations.

Version: 4.0.0
Author: Your Team
License: MIT
"""

__version__ = "4.0.0"
__author__ = "Your Team"

from .parsers import LogParser
from .utils import patterns, enrichment, io_utils

__all__ = [
    "LogParser",
    "patterns",
    "enrichment",
    "io_utils",
]
