"""
Statistical Metrics
===================

Functions for computing statistical metrics and aggregations on log data.
"""

import numpy as np
import pandas as pd
from typing import Tuple


def module_ranking(df: pd.DataFrame) -> pd.DataFrame:
    """
    Rank modules by error rate and volume.
    
    Calculates aggregate metrics per module including:
    - Total log entries
    - Error count
    - Warning count
    - Error rate
    - First/last seen timestamps
    - Line type distribution
    
    Args:
        df: Log DataFrame with 'module' and 'level' columns
        
    Returns:
        pd.DataFrame: Module ranking sorted by errors (desc)
        
    Columns:
        - module: Module name
        - total: Total entries
        - errors: Error count
        - warns: Warning count
        - error_rate: errors / total
        - first_seen: Earliest timestamp
        - last_seen: Latest timestamp
        - [line_type columns]: Counts per type if available
    """
    if df.empty or "module" not in df.columns:
        return pd.DataFrame()
    
    # Efficient boolean indexing
    is_error = df["level"].astype(str).str.upper() == "ERROR"
    is_warn = df["level"].astype(str).str.upper().isin(["WARN", "WARNING"])
    
    # Aggregate metrics
    result = df.groupby("module", dropna=False).agg(
        total=("message", "count"),
        errors=("message", lambda x: is_error[x.index].sum()),
        warns=("message", lambda x: is_warn[x.index].sum()),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max")
    ).reset_index()
    
    result["error_rate"] = (result["errors"] / result["total"]).round(3)
    
    # Add line type distribution if available
    if "line_type" in df.columns:
        types_pivot = df.pivot_table(
            index="module",
            columns="line_type",
            values="message",
            aggfunc="count",
            fill_value=0
        )
        result = result.merge(
            types_pivot.reset_index(),
            on="module",
            how="left"
        )
    
    return result.sort_values(
        ["errors", "error_rate", "total"],
        ascending=[False, False, False]
    )


def hourly_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate hourly aggregated metrics.
    
    Computes rolling statistics for anomaly detection:
    - Log count per hour
    - Error count per hour
    - Error ratio
    - Z-scores for volume and errors
    - Spike detection
    
    Args:
        df: Log DataFrame with 'timestamp' and 'level' columns
        
    Returns:
        pd.DataFrame: Hourly metrics with anomaly indicators
        
    Columns:
        - timestamp: Hour bucket
        - count: Total logs this hour
        - errors: Error count this hour
        - error_ratio: errors / count
        - count_ma: Moving average (24h)
        - count_std: Rolling std dev
        - z_count: Z-score for volume
        - errors_ma: Moving average of errors
        - errors_std: Rolling std dev of errors
        - z_errors: Z-score for errors
        - spike: Boolean anomaly indicator
    """
    if df.empty or "timestamp" not in df.columns or df["timestamp"].isna().all():
        return pd.DataFrame()
    
    # Prepare data
    tmp = df[df["timestamp"].notna()].copy()
    tmp["is_error"] = tmp["level"].astype(str).str.upper() == "ERROR"
    tmp = tmp.set_index("timestamp").sort_index()
    
    # Resample to hourly buckets
    grp = tmp.resample("1H")
    res = pd.DataFrame({
        "count": grp.size(),
        "errors": grp["is_error"].sum(),
    })
    
    res["error_ratio"] = (res["errors"] / res["count"]).fillna(0.0)
    
    # Rolling statistics (24-hour window)
    window = 24
    res["count_ma"] = res["count"].rolling(window, min_periods=6).mean()
    res["count_std"] = res["count"].rolling(window, min_periods=6).std(ddof=0)
    res["z_count"] = (res["count"] - res["count_ma"]) / res["count_std"].replace(0, np.nan)
    
    res["errors_ma"] = res["errors"].rolling(window, min_periods=6).mean()
    res["errors_std"] = res["errors"].rolling(window, min_periods=6).std(ddof=0)
    res["z_errors"] = (res["errors"] - res["errors_ma"]) / res["errors_std"].replace(0, np.nan)
    
    # Spike detection (z > 3 or error_ratio > 0.5)
    res["spike"] = (
        (res["z_count"].abs() > 3) |
        (res["z_errors"].abs() > 3) |
        (res["error_ratio"] > 0.5)
    )
    
    return res.reset_index()


def http_stats(df: pd.DataFrame) -> Tuple[pd.Series, pd.Series]:
    """
    Calculate HTTP request statistics.
    
    Extracts and aggregates HTTP-specific metrics:
    - Top requested paths
    - Status code distribution
    
    Args:
        df: Log DataFrame with 'message' column
        
    Returns:
        Tuple[pd.Series, pd.Series]:
            - top_paths: Top 20 requested paths with counts
            - status_dist: Status code distribution
    """
    if df.empty or "message" not in df.columns:
        return pd.Series(dtype=int), pd.Series(dtype=int)
    
    # Filter HTTP logs
    http_df = df[
        df["message"].astype(str).str.contains("HTTP/", na=False)
    ].copy()
    
    if http_df.empty:
        return pd.Series(dtype=int), pd.Series(dtype=int)
    
    # Extract path from request_path if available, else from message
    if "request_path" in http_df.columns:
        paths = http_df["request_path"]
    else:
        from ..utils.patterns import CP
        paths = http_df["message"].str.extract(CP.HTTP_PATH, expand=False)
    
    # Extract status code
    if "status_code" in http_df.columns:
        status = http_df["status_code"]
    else:
        from ..utils.patterns import CP
        status = http_df["message"].str.extract(CP.HTTP_STATUS, expand=False)
    
    top_paths = paths.value_counts().head(20)
    status_dist = status.value_counts().sort_index()
    
    return top_paths, status_dist


__all__ = [
    "module_ranking",
    "hourly_metrics",
    "http_stats",
]
