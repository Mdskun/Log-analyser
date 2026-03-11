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

    Calculates aggregate metrics per module including total entries,
    error/warning counts, error rate, first/last seen timestamps,
    and an optional line-type breakdown.

    Args:
        df: Log DataFrame with at least 'module', 'level', and 'message' columns.

    Returns:
        pd.DataFrame sorted by errors descending, then error_rate, then total.
    """
    if df.empty or "module" not in df.columns:
        return pd.DataFrame()

    is_error = df["level"].astype(str).str.upper() == "ERROR"
    is_warn = df["level"].astype(str).str.upper().isin(["WARN", "WARNING"])

    result = df.groupby("module", dropna=False).agg(
        total=("message", "count"),
        errors=("message", lambda x: is_error[x.index].sum()),
        warns=("message", lambda x: is_warn[x.index].sum()),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()

    result["error_rate"] = (result["errors"] / result["total"]).round(3)

    if "line_type" in df.columns:
        types_pivot = df.pivot_table(
            index="module",
            columns="line_type",
            values="message",
            aggfunc="count",
            fill_value=0,
        )
        result = result.merge(types_pivot.reset_index(), on="module", how="left")

    return result.sort_values(
        ["errors", "error_rate", "total"],
        ascending=[False, False, False],
    )


def hourly_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate hourly aggregated metrics for anomaly detection.

    Computes per-hour counts and rolling z-scores. Flags hours where
    volume or error rate is statistically anomalous (|z| > 3 or
    error_ratio > 0.5).

    Args:
        df: Log DataFrame with 'timestamp' and 'level' columns.

    Returns:
        pd.DataFrame of hourly metrics with a 'spike' boolean column.
    """
    if df.empty or "timestamp" not in df.columns or df["timestamp"].isna().all():
        return pd.DataFrame()

    tmp = df[df["timestamp"].notna()].copy()
    tmp["is_error"] = tmp["level"].astype(str).str.upper() == "ERROR"
    tmp = tmp.set_index("timestamp").sort_index()

    # Use "h" — the "1H" alias was deprecated in pandas 2.2
    grp = tmp.resample("h")
    res = pd.DataFrame({
        "count": grp.size(),
        "errors": grp["is_error"].sum(),
    })

    res["error_ratio"] = (res["errors"] / res["count"]).fillna(0.0)

    window = 24
    res["count_ma"] = res["count"].rolling(window, min_periods=6).mean()
    res["count_std"] = res["count"].rolling(window, min_periods=6).std(ddof=0)
    res["z_count"] = (res["count"] - res["count_ma"]) / res["count_std"].replace(0, np.nan)

    res["errors_ma"] = res["errors"].rolling(window, min_periods=6).mean()
    res["errors_std"] = res["errors"].rolling(window, min_periods=6).std(ddof=0)
    res["z_errors"] = (res["errors"] - res["errors_ma"]) / res["errors_std"].replace(0, np.nan)

    res["spike"] = (
        (res["z_count"].abs() > 3)
        | (res["z_errors"].abs() > 3)
        | (res["error_ratio"] > 0.5)
    )

    return res.reset_index()


def http_stats(df: pd.DataFrame) -> Tuple[pd.Series, pd.Series]:
    """
    Calculate HTTP request statistics.

    Args:
        df: Log DataFrame with 'message' column (and optionally
            'request_path' and 'status_code').

    Returns:
        Tuple of (top_paths, status_dist) as pd.Series.
    """
    if df.empty or "message" not in df.columns:
        return pd.Series(dtype=int), pd.Series(dtype=int)

    http_df = df[df["message"].astype(str).str.contains("HTTP/", na=False)].copy()
    if http_df.empty:
        return pd.Series(dtype=int), pd.Series(dtype=int)

    if "request_path" in http_df.columns:
        paths = http_df["request_path"]
    else:
        from ..utils.patterns import CP
        paths = http_df["message"].str.extract(CP.HTTP_PATH, expand=False)

    if "status_code" in http_df.columns:
        status = http_df["status_code"]
    else:
        from ..utils.patterns import CP
        status = http_df["message"].str.extract(CP.HTTP_STATUS, expand=False)

    return paths.value_counts().head(20), status.value_counts().sort_index()


__all__ = ["module_ranking", "hourly_metrics", "http_stats"]
