"""
Tests for src/analytics — module_ranking, hourly_metrics, cluster_errors,
extract_top_error_phrases, sequence_mining.
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

from src.analytics.metrics import module_ranking, hourly_metrics
from src.analytics.ml_analytics import (
    cluster_errors, extract_top_error_phrases, sequence_mining,
)


# ============================================================
# module_ranking
# ============================================================

class TestModuleRanking:
    def test_returns_dataframe(self, sample_df):
        result = module_ranking(sample_df)
        assert isinstance(result, pd.DataFrame)

    def test_empty_input(self, empty_df):
        assert module_ranking(empty_df).empty

    def test_required_columns_present(self, sample_df):
        result = module_ranking(sample_df)
        for col in ("module", "total", "errors", "warns", "error_rate"):
            assert col in result.columns

    def test_sorted_by_errors_desc(self, sample_df):
        result = module_ranking(sample_df)
        assert result["errors"].is_monotonic_decreasing or len(result) <= 1

    def test_error_rate_between_0_and_1(self, sample_df):
        result = module_ranking(sample_df)
        assert (result["error_rate"] >= 0).all()
        assert (result["error_rate"] <= 1).all()

    def test_total_equals_sum_of_levels(self, sample_df):
        result = module_ranking(sample_df)
        for _, row in result.iterrows():
            mod_df = sample_df[sample_df["module"] == row["module"]]
            assert row["total"] == len(mod_df)


# ============================================================
# hourly_metrics
# ============================================================

class TestHourlyMetrics:
    def _make_df(self, n_hours=48):
        """Generate synthetic hourly log data."""
        base = datetime(2024, 1, 1)
        rows = []
        for h in range(n_hours):
            ts = base + timedelta(hours=h)
            rows.append({"timestamp": ts, "level": "INFO",    "message": "ok"})
            rows.append({"timestamp": ts, "level": "ERROR",   "message": "fail"})
            rows.append({"timestamp": ts, "level": "WARNING", "message": "warn"})
        return pd.DataFrame(rows)

    def test_returns_dataframe(self):
        result = hourly_metrics(self._make_df())
        assert isinstance(result, pd.DataFrame)

    def test_empty_input(self, empty_df):
        assert hourly_metrics(empty_df).empty

    def test_no_timestamp_column(self):
        df = pd.DataFrame({"level": ["INFO", "ERROR"]})
        assert hourly_metrics(df).empty

    def test_required_columns(self):
        result = hourly_metrics(self._make_df())
        for col in ("timestamp", "count", "errors", "error_ratio", "spike"):
            assert col in result.columns

    def test_error_ratio_bounded(self):
        result = hourly_metrics(self._make_df())
        assert (result["error_ratio"] >= 0).all()
        assert (result["error_ratio"] <= 1).all()

    def test_spike_is_boolean(self):
        result = hourly_metrics(self._make_df())
        assert result["spike"].dtype == bool

    def test_uses_h_not_1H_alias(self):
        """Ensure no DeprecationWarning from old pandas resample alias."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            hourly_metrics(self._make_df())   # must not raise


# ============================================================
# cluster_errors
# ============================================================

class TestClusterErrors:
    def _error_df(self, n=20):
        messages = [
            "Connection refused to db host",
            "Database timeout after 30s",
            "Failed to connect to postgres",
            "Auth token expired for user",
            "Invalid credentials provided",
        ]
        rows = []
        for i in range(n):
            rows.append({
                "level": "ERROR",
                "message": messages[i % len(messages)],
            })
        return pd.DataFrame(rows)

    def test_returns_list(self):
        result = cluster_errors(self._error_df())
        assert isinstance(result, list)

    def test_empty_input(self, empty_df):
        assert cluster_errors(empty_df) == []

    def test_no_errors_in_df(self):
        df = pd.DataFrame([{"level": "INFO", "message": "all good"}] * 5)
        assert cluster_errors(df) == []

    def test_single_error_returns_empty(self):
        df = pd.DataFrame([{"level": "ERROR", "message": "one error"}])
        assert cluster_errors(df) == []

    def test_returns_tuples_of_message_and_label(self):
        result = cluster_errors(self._error_df(), n_clusters=2)
        assert all(isinstance(r, tuple) and len(r) == 2 for r in result)

    def test_n_clusters_respected(self):
        result = cluster_errors(self._error_df(n=30), n_clusters=3)
        labels = {label for _, label in result}
        assert len(labels) <= 3


# ============================================================
# extract_top_error_phrases
# ============================================================

class TestExtractTopErrorPhrases:
    def test_returns_dataframe(self):
        msgs = pd.Series(["connection refused to db"] * 10 + ["auth token expired"] * 5)
        result = extract_top_error_phrases(msgs)
        assert isinstance(result, pd.DataFrame)

    def test_has_ngram_and_count_columns(self):
        msgs = pd.Series(["connection refused to db"] * 10)
        result = extract_top_error_phrases(msgs)
        assert "ngram" in result.columns
        assert "count" in result.columns

    def test_empty_input(self):
        result = extract_top_error_phrases(pd.Series([], dtype=str))
        assert result.empty

    def test_sorted_descending(self):
        msgs = pd.Series(["connection refused to db"] * 10 + ["auth token expired"] * 5)
        result = extract_top_error_phrases(msgs)
        assert result["count"].is_monotonic_decreasing


# ============================================================
# sequence_mining
# ============================================================

class TestSequenceMining:
    def _make_df(self):
        base = datetime(2024, 1, 1, 10, 0)
        rows = []
        for i in range(30):
            ts = base + timedelta(minutes=i)
            level = "ERROR" if i % 5 == 4 else "INFO"
            rows.append({
                "timestamp": ts,
                "level": level,
                "line_type": "TIMEOUT" if level == "ERROR" else "HTTP_ACCESS",
                "module": "api" if i % 2 == 0 else "db",
                "message": "event",
            })
        return pd.DataFrame(rows)

    def test_returns_dataframe(self):
        result = sequence_mining(self._make_df())
        assert isinstance(result, pd.DataFrame)

    def test_empty_input(self, empty_df):
        assert sequence_mining(empty_df).empty

    def test_no_timestamp(self):
        df = pd.DataFrame([{"level": "ERROR", "message": "err"}])
        assert sequence_mining(df).empty

    def test_columns_present(self):
        result = sequence_mining(self._make_df())
        if not result.empty:
            assert "sequence" in result.columns
            assert "count" in result.columns
