"""
ML Analytics
============

Machine learning-based analytics: clustering, phrase extraction, and sequence mining.
These functions were previously in the monolithic Analyser.py and have been
moved here as part of the modular src/ refactor.
"""

import pandas as pd
from typing import List, Tuple
from datetime import timedelta

from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.cluster import KMeans


def cluster_errors(df: pd.DataFrame, n_clusters: int = 5) -> List[Tuple[str, int]]:
    """
    Cluster error messages using KMeans + TF-IDF.

    Args:
        df: Log DataFrame with 'level' and 'message' columns
        n_clusters: Number of clusters to produce

    Returns:
        List of (message, cluster_label) tuples, or [] if not enough data
    """
    if df.empty or "level" not in df.columns:
        return []

    error_msgs = df[df["level"].astype(str).str.upper() == "ERROR"]["message"].fillna("")
    if len(error_msgs) < 2:
        return []

    try:
        vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
        X = vectorizer.fit_transform(error_msgs)

        n = min(n_clusters, len(error_msgs))
        model = KMeans(n_clusters=n, random_state=42, n_init=10)
        labels = model.fit_predict(X)

        return list(zip(error_msgs, labels))
    except Exception:
        return []


def extract_top_error_phrases(messages: pd.Series, top_n: int = 10) -> pd.DataFrame:
    """
    Extract the most frequent n-grams from error messages.

    Args:
        messages: Series of error message strings
        top_n: Number of top phrases to return

    Returns:
        pd.DataFrame with columns ['ngram', 'count'] sorted descending
    """
    msgs = [m for m in messages.fillna("") if m]
    if not msgs:
        return pd.DataFrame(columns=["ngram", "count"])

    try:
        vectorizer = CountVectorizer(
            ngram_range=(2, 3),
            stop_words="english",
            max_features=2000,
        )
        X = vectorizer.fit_transform(msgs)
        freqs = X.sum(axis=0).A1
        terms = vectorizer.get_feature_names_out()

        freq_df = pd.DataFrame({"ngram": terms, "count": freqs})
        return freq_df.sort_values("count", ascending=False).head(top_n)
    except Exception:
        return pd.DataFrame(columns=["ngram", "count"])


def sequence_mining(
    df: pd.DataFrame,
    window_minutes: int = 5,
    seq_len: int = 3,
    top_k: int = 15,
) -> pd.DataFrame:
    """
    Mine common event sequences that precede error log entries.

    Args:
        df: Log DataFrame with 'timestamp', 'level', 'line_type', 'module' columns
        window_minutes: Look-back window before each error
        seq_len: Maximum sequence length to generate
        top_k: Number of top sequences to return

    Returns:
        pd.DataFrame with columns ['sequence', 'count'] sorted descending,
        or empty DataFrame if no sequences found
    """
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["sequence", "count"])

    work = df.sort_values("timestamp").copy()
    work["is_error"] = work["level"].astype(str).str.upper() == "ERROR"

    sequences = []
    error_rows = work[work["is_error"]]

    for _, row in error_rows.iterrows():
        cutoff = row["timestamp"] - timedelta(minutes=window_minutes)
        window = work[
            (work["timestamp"] >= cutoff) & (work["timestamp"] < row["timestamp"])
        ].tail(100)

        if window.empty:
            continue

        toks = (
            window["line_type"].fillna("NA") + ":"
            + window["module"].astype(str).fillna("NA")
        ).tolist()

        for length in range(2, seq_len + 1):
            start = max(0, len(toks) - 50)
            for i in range(start, len(toks) - length + 1):
                sequences.append(tuple(toks[i : i + length]))

    if not sequences:
        return pd.DataFrame(columns=["sequence", "count"])

    seq_series = pd.Series(sequences).value_counts().head(top_k)
    return seq_series.rename_axis("sequence").reset_index(name="count")


__all__ = [
    "cluster_errors",
    "extract_top_error_phrases",
    "sequence_mining",
]
