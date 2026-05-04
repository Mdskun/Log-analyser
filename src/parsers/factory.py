"""
Log Parser Factory
==================

Main parser interface and factory for selecting appropriate parser.

Supports custom format configurations for flexible log parsing.
"""

import pandas as pd
from typing import Iterator, Callable, Dict, Optional, Any
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
from .apache_modjk import (
    analyze_apache_modjk,
    analyze_tomcat_connector,
)


class LogParser:
    """
    Factory class for log parsing with custom format support.
    
    Provides unified interface for parsing various log formats.
    Supports custom format configurations for flexible parsing.
    
    Example:
        >>> parser = LogParser()
        >>> df = parser.parse(lines, "apache_modjk")
        >>> print(df.head())
        
        >>> # With custom format config
        >>> config = {'timestamp_format': '%d/%b/%Y:%H:%M:%S'}
        >>> df = parser.parse(lines, "apache_modjk", config)
    """
    
    # Registry of available parsers with metadata
    PARSERS: Dict[str, Dict[str, Any]] = {
        "custom": {
            "func": analyze_custom,
            "description": "Custom structured format: [timestamp] [level] [module] message",
            "supports_config": False,
        },
        "json": {
            "func": analyze_json,
            "description": "JSON log format",
            "supports_config": False,
        },
        "syslog": {
            "func": analyze_syslog,
            "description": "Syslog format: Mon DD HH:MM:SS hostname service[pid]: message",
            "supports_config": False,
        },
        "apache": {
            "func": analyze_apache,
            "description": "Apache Combined Log Format",
            "supports_config": False,
        },
        "apache_modjk": {
            "func": analyze_apache_modjk,
            "description": "Apache mod_jk/Tomcat connector format: [timestamp] [severity] message",
            "supports_config": True,
            "config_keys": ["timestamp_format", "severity_key", "message_key"],
        },
        "tomcat_connector": {
            "func": analyze_tomcat_connector,
            "description": "Tomcat connector logs",
            "supports_config": False,
        },
        "docker_json": {
            "func": analyze_docker_json,
            "description": "Docker JSON log format",
            "supports_config": False,
        },
        "kubernetes_json": {
            "func": analyze_kubernetes_json,
            "description": "Kubernetes JSON format",
            "supports_config": False,
        },
        "cloudwatch_export": {
            "func": analyze_cloudwatch,
            "description": "AWS CloudWatch export format",
            "supports_config": False,
        },
        "gcp_cloud_logging": {
            "func": analyze_gcp_cloud_logging,
            "description": "GCP Cloud Logging format",
            "supports_config": False,
        },
        "windows_event_xml": {
            "func": analyze_windows_event_xml,
            "description": "Windows Event Log XML format",
            "supports_config": False,
        },
        "generic": {
            "func": analyze_generic,
            "description": "Generic format (fallback with heuristics)",
            "supports_config": False,
        },
    }
    
    @classmethod
    def parse(cls, lines: Iterator[str], 
              format: str,
              format_config: Optional[Dict[str, str]] = None) -> pd.DataFrame:
        """
        Parse log lines using appropriate parser.
        
        Args:
            lines: Iterator of log lines
            format: Detected format name
            format_config: Optional custom format configuration dict
            
        Returns:
            pd.DataFrame: Parsed log data
            
        Raises:
            ValueError: If format is not supported
            
        Example:
            >>> lines = iter(["[2024-01-01 00:00:00] [INFO] [api] Starting"])
            >>> df = LogParser.parse(lines, "custom")
            
            >>> # With custom timestamp format
            >>> config = {'timestamp_format': '%a %b %d %H:%M:%S %Y'}
            >>> df = LogParser.parse(lines, "apache_modjk", config)
        """
        parser_info = cls.PARSERS.get(format)
        
        if not parser_info:
            # Fallback to generic
            parser_info = cls.PARSERS["generic"]
        
        parser_func = parser_info["func"]
        
        # Check if parser supports config
        if format_config and parser_info.get("supports_config", False):
            if format in ["apache_modjk", "tomcat_connector"]:
                return parser_func(lines, format_config)
            else:
                return parser_func(lines)
        else:
            return parser_func(lines)
    
    @classmethod
    def get_supported_formats(cls) -> list:
        """
        Get list of supported log formats.
        
        Returns:
            list: Format names
        """
        return list(cls.PARSERS.keys())
    
    @classmethod
    def get_format_info(cls, format: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific format.
        
        Args:
            format: Format name
            
        Returns:
            Format metadata dictionary or None
            
        Example:
            >>> info = LogParser.get_format_info("apache_modjk")
            >>> print(info['description'])
        """
        return cls.PARSERS.get(format)
    
    @classmethod
    def get_all_format_info(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all supported formats.
        
        Returns:
            Dictionary of format metadata
        """
        return {
            fmt: {
                "description": info.get("description", ""),
                "supports_config": info.get("supports_config", False),
                "config_keys": info.get("config_keys", []),
            }
            for fmt, info in cls.PARSERS.items()
        }
    
    @classmethod
    def register_parser(cls, format_name: str, 
                       parser_func: Callable[[Iterator[str]], pd.DataFrame],
                       description: str = "",
                       supports_config: bool = False,
                       config_keys: Optional[list] = None):
        """
        Register a custom parser.
        
        Args:
            format_name: Unique format identifier
            parser_func: Parser function
            description: Human-readable description
            supports_config: Whether parser accepts format_config parameter
            config_keys: List of configuration keys supported
            
        Example:
            >>> def my_parser(lines):
            ...     # Custom parsing logic
            ...     return pd.DataFrame(...)
            >>> LogParser.register_parser(
            ...     "my_format", 
            ...     my_parser,
            ...     "My custom log format",
            ...     supports_config=True,
            ...     config_keys=["timestamp_format"]
            ... )
        """
        cls.PARSERS[format_name] = {
            "func": parser_func,
            "description": description,
            "supports_config": supports_config,
            "config_keys": config_keys or [],
        }


__all__ = ["LogParser"]
