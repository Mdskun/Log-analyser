"""
JSON Format Parsers
===================

Parsers for JSON-based log formats (generic JSON, Docker, Kubernetes, cloud providers).
"""

import json
import pandas as pd
from typing import Iterator
from .base import BaseAnalyzer


def analyze_json(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse generic JSON logs.
    
    Handles various JSON logging frameworks with flexible field extraction.
    
    Args:
        lines: Iterator of JSON log lines
        
    Returns:
        pd.DataFrame: Parsed logs
    """
    rows = []
    
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            row = BaseAnalyzer.extract_common_json_fields(obj)
            row["module"] = (
                obj.get("module") or 
                obj.get("logger") or 
                obj.get("logName") or 
                obj.get("logStream") or 
                "unknown"
            )
            rows.append(row)
    
    return pd.DataFrame(rows)


def analyze_docker_json(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse Docker JSON file driver logs.
    
    Format: {"log": "...", "time": "...", "stream": "stdout"}
    
    Args:
        lines: Iterator of Docker JSON log lines
        
    Returns:
        pd.DataFrame: Parsed logs
    """
    rows = []
    
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            rows.append({
                "timestamp": obj.get("time"),
                "level": obj.get("level", "INFO"),
                "module": (
                    obj.get("container_name") or 
                    obj.get("source") or 
                    "docker"
                ),
                "message": (obj.get("log") or "").rstrip(),
                "ip": None,
                "user_agent": obj.get("user_agent"),
            })
    
    return pd.DataFrame(rows)


def analyze_kubernetes_json(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse Kubernetes JSON logs.
    
    Extracts Kubernetes metadata (namespace, pod, container).
    
    Args:
        lines: Iterator of K8s JSON log lines
        
    Returns:
        pd.DataFrame: Parsed logs with K8s metadata
    """
    rows = []
    
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            k8s = obj.get("kubernetes", {}) if isinstance(obj, dict) else {}
            
            # Build hierarchical module name
            module = "/".join(filter(None, [
                k8s.get("namespace_name"),
                k8s.get("pod_name"),
                k8s.get("container_name")
            ])) or "kubernetes"
            
            rows.append({
                "timestamp": obj.get("time") or obj.get("timestamp"),
                "level": obj.get("level") or obj.get("severity") or "INFO",
                "module": module,
                "message": obj.get("log") or obj.get("message") or "",
                "ip": None,
                "user_agent": (
                    obj.get("userAgent") or 
                    obj.get("httpUserAgent")
                ),
            })
    
    return pd.DataFrame(rows)


def analyze_cloudwatch(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse AWS CloudWatch Logs export JSON.
    
    Format: {"logGroup": "...", "logStream": "...", "message": "...", "timestamp": ...}
    
    Args:
        lines: Iterator of CloudWatch JSON log lines
        
    Returns:
        pd.DataFrame: Parsed logs
    """
    rows = []
    
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            rows.append({
                "timestamp": obj.get("timestamp"),
                "level": obj.get("level") or obj.get("severity") or "INFO",
                "module": (
                    obj.get("logGroup") or 
                    obj.get("logStream") or 
                    "cloudwatch"
                ),
                "message": obj.get("message") or obj.get("@message") or "",
                "ip": None,
                "user_agent": obj.get("userAgent")
            })
    
    return pd.DataFrame(rows)


def analyze_gcp_cloud_logging(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse GCP Cloud Logging export JSON.
    
    Handles textPayload, jsonPayload, and protoPayload.
    
    Args:
        lines: Iterator of GCP JSON log lines
        
    Returns:
        pd.DataFrame: Parsed logs
    """
    rows = []
    
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            # Extract message from various payload types
            msg = obj.get("textPayload")
            if not msg and isinstance(obj.get("jsonPayload"), dict):
                msg = json.dumps(obj["jsonPayload"], ensure_ascii=False)
            if not msg and isinstance(obj.get("protoPayload"), dict):
                msg = json.dumps(obj["protoPayload"], ensure_ascii=False)
            
            # Extract user agent from httpRequest if present
            http_req = obj.get("httpRequest", {})
            user_agent = None
            if isinstance(http_req, dict):
                user_agent = http_req.get("userAgent")
            
            rows.append({
                "timestamp": (
                    obj.get("timestamp") or 
                    obj.get("receiveTimestamp")
                ),
                "level": obj.get("severity", "INFO"),
                "module": (obj.get("logName") or "gcp").split("/")[-1],
                "message": msg or "",
                "ip": None,
                "user_agent": user_agent,
            })
    
    return pd.DataFrame(rows)


__all__ = [
    "analyze_json",
    "analyze_docker_json",
    "analyze_kubernetes_json",
    "analyze_cloudwatch",
    "analyze_gcp_cloud_logging",
]
