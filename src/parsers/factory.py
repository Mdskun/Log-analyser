"""
Log Parser Factory
==================

Main parser interface and factory for selecting appropriate parser.
"""

import pandas as pd
from typing import Iterator, Callable, Dict
from .standard import (
    analyze_custom,
    analyze_syslog,
    analyze_apache,
    analyze_generic,
)
from .json_parsers import (
    analyze_json,
    analyze_docker_json,
    analyze_kubernetes_json,
    analyze_cloudwatch,
    analyze_gcp_cloud_logging,
)
from .xml_parsers import analyze_windows_event_xml


class LogParser:
    """
    Factory class for log parsing.
    
    Provides unified interface for parsing various log formats.
    
    Example:
        >>> parser = LogParser()
        >>> df = parser.parse(lines, "apache")
        >>> print(df.head())
    """
    
    # Registry of available parsers
    PARSERS: Dict[str, Callable[[Iterator[str]], pd.DataFrame]] = {
        "custom": analyze_custom,
        "json": analyze_json,
        "syslog": analyze_syslog,
        "apache": analyze_apache,
        "docker_json": analyze_docker_json,
        "kubernetes_json": analyze_kubernetes_json,
        "cloudwatch_export": analyze_cloudwatch,
        "gcp_cloud_logging": analyze_gcp_cloud_logging,
        "windows_event_xml": analyze_windows_event_xml,
        "generic": analyze_generic,
    }
    
    @classmethod
    def parse(cls, lines: Iterator[str], format: str) -> pd.DataFrame:
        """
        Parse log lines using appropriate parser.
        
        Args:
            lines: Iterator of log lines
            format: Detected format name
            
        Returns:
            pd.DataFrame: Parsed log data
            
        Raises:
            ValueError: If format is not supported
            
        Example:
            >>> lines = iter(["[2024-01-01 00:00:00] [INFO] [api] Starting"])
            >>> df = LogParser.parse(lines, "custom")
        """
        parser = cls.PARSERS.get(format, analyze_generic)
        return parser(lines)
    
    @classmethod
    def get_supported_formats(cls) -> list:
        """
        Get list of supported log formats.
        
        Returns:
            list: Format names
        """
        return list(cls.PARSERS.keys())
    
    @classmethod
    def register_parser(cls, format_name: str, 
                       parser_func: Callable[[Iterator[str]], pd.DataFrame]):
        """
        Register a custom parser.
        
        Args:
            format_name: Unique format identifier
            parser_func: Parser function
            
        Example:
            >>> def my_parser(lines):
            ...     # Custom parsing logic
            ...     return pd.DataFrame(...)
            >>> LogParser.register_parser("my_format", my_parser)
        """
        cls.PARSERS[format_name] = parser_func


__all__ = ["LogParser"]
