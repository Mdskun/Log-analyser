"""
Base Parser Classes
===================

Base classes and utilities for log parsers.
"""

import json
import pandas as pd
from typing import Dict, Optional, Iterator


class BaseAnalyzer:
    """
    Base class for log analyzers.
    
    Provides common functionality for all parser implementations
    to reduce code duplication and ensure consistency.
    """
    
    @staticmethod
    def safe_parse_json(line: str) -> Optional[Dict]:
        """
        Safely parse JSON line.
        
        Args:
            line: JSON string
            
        Returns:
            Optional[Dict]: Parsed JSON object or None on error
        """
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None
    
    @staticmethod
    def extract_common_json_fields(obj: Dict) -> Dict:
        """
        Extract common fields from JSON log objects.
        
        Handles various field naming conventions across different
        logging frameworks and platforms.
        
        Args:
            obj: Parsed JSON object
            
        Returns:
            Dict: Standardized field dictionary
            
        Standard Fields:
            - timestamp: Event timestamp
            - level: Log level/severity
            - message: Log message
            - ip: Source IP address
            - user_agent: User agent string
            - status_code: HTTP status code
            - request_time: Request/response time
        """
        return {
            "timestamp": (
                obj.get("timestamp") or 
                obj.get("time") or 
                obj.get("@timestamp")
            ),
            "level": (
                obj.get("level") or 
                obj.get("severity") or 
                obj.get("logLevel") or 
                "UNKNOWN"
            ),
            "message": (
                obj.get("message") or 
                obj.get("msg") or 
                obj.get("log") or 
                obj.get("textPayload") or 
                ""
            ),
            "ip": (
                obj.get("ip") or 
                obj.get("client_ip")
            ),
            "user_agent": (
                obj.get("user_agent") or 
                obj.get("userAgent") or 
                obj.get("httpUserAgent")
            ),
            "status_code": (
                obj.get("status") or 
                obj.get("status_code")
            ),
            "request_time": (
                obj.get("response_time") or 
                obj.get("latency") or 
                obj.get("request_time")
            ),
        }
    
    @staticmethod
    def create_dataframe(data: list) -> pd.DataFrame:
        """
        Create DataFrame from parsed log data.
        
        Args:
            data: List of log entry dictionaries
            
        Returns:
            pd.DataFrame: Log data as DataFrame
        """
        return pd.DataFrame(data)


__all__ = ["BaseAnalyzer"]
