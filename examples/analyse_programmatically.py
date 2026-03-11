"""
Programmatic usage example — Log Analyzer Pro
=============================================

This script shows how to use the library without Streamlit.
Run it from the repo root:

    python examples/analyse_programmatically.py

Or point it at your own log file:

    python examples/analyse_programmatically.py /path/to/your.log
"""

import sys
from pathlib import Path

# Make sure the repo root is on the path when running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.parsers import LogParser
from src.utils.io_utils import detect_format, iter_lines
from src.utils.enrichment import add_enrichments, redact_pii
from src.analytics.metrics import module_ranking, hourly_metrics, http_stats
from src.analytics.ml_analytics import (
    cluster_errors,
    extract_top_error_phrases,
    sequence_mining,
)


# ---------------------------------------------------------------------------
# Pick which sample file to analyse
# ---------------------------------------------------------------------------

EXAMPLES_DIR = Path(__file__).parent

SAMPLE_FILES = {
    "apache":  EXAMPLES_DIR / "sample_apache.log",
    "syslog":  EXAMPLES_DIR / "sample_syslog.log",
    "custom":  EXAMPLES_DIR / "sample_custom.log",
    "json":    EXAMPLES_DIR / "sample_app.json",
}

# Accept a CLI argument, otherwise default to the custom format
if len(sys.argv) > 1:
    log_path = Path(sys.argv[1])
else:
    log_path = SAMPLE_FILES["custom"]

print(f"\n{'='*60}")
print(f"  Log Analyzer Pro — Programmatic Example")
print(f"{'='*60}")
print(f"  File : {log_path.name}")


# ---------------------------------------------------------------------------
# 1. Read and parse
# ---------------------------------------------------------------------------

with open(log_path, "rb") as f:
    lines = list(iter_lines(f))

fmt = detect_format(tuple(lines[:50]))
print(f"  Format detected : {fmt}\n")

df = LogParser.parse(iter(lines), fmt)
print(f"Parsed {len(df)} log entries.")

if df.empty:
    print("No entries parsed — check the file format.")
    sys.exit(0)


# ---------------------------------------------------------------------------
# 2. Enrich
# ---------------------------------------------------------------------------

df = add_enrichments(df)
print(f"Columns after enrichment: {list(df.columns)}\n")


# ---------------------------------------------------------------------------
# 3. Basic summary
# ---------------------------------------------------------------------------

level_counts = df["level"].value_counts()
print("── Level breakdown ──────────────────")
for level, count in level_counts.items():
    bar = "█" * min(count, 40)
    print(f"  {level:<10} {count:>4}  {bar}")
print()


# ---------------------------------------------------------------------------
# 4. Module ranking
# ---------------------------------------------------------------------------

ranking = module_ranking(df)
if not ranking.empty:
    print("── Module ranking (by errors) ────────")
    print(
        ranking[["module", "total", "errors", "warns", "error_rate"]]
        .head(8)
        .to_string(index=False)
    )
    print()


# ---------------------------------------------------------------------------
# 5. Anomaly detection
# ---------------------------------------------------------------------------

metrics = hourly_metrics(df)
if not metrics.empty:
    spikes = metrics[metrics["spike"]]
    print("── Hourly anomalies ──────────────────")
    if spikes.empty:
        print("  No anomalous hours detected.")
    else:
        print(spikes[["timestamp", "count", "errors", "error_ratio", "z_count"]].to_string(index=False))
    print()


# ---------------------------------------------------------------------------
# 6. HTTP statistics (if applicable)
# ---------------------------------------------------------------------------

top_paths, status_dist = http_stats(df)
if not top_paths.empty:
    print("── Top 5 requested paths ─────────────")
    for path, count in top_paths.head(5).items():
        print(f"  {count:>4}  {path}")
    print()

    print("── HTTP status distribution ──────────")
    for code, count in status_dist.items():
        print(f"  {code}  {count:>4}")
    print()


# ---------------------------------------------------------------------------
# 7. Error clustering (ML)
# ---------------------------------------------------------------------------

clusters = cluster_errors(df, n_clusters=3)
if clusters:
    print("── Error clusters ────────────────────")
    from itertools import groupby
    clusters_sorted = sorted(clusters, key=lambda x: x[1])
    for label, group in groupby(clusters_sorted, key=lambda x: x[1]):
        messages = [m for m, _ in group]
        print(f"\n  Cluster {label} ({len(messages)} errors):")
        for msg in messages[:3]:
            print(f"    • {msg[:80]}")
        if len(messages) > 3:
            print(f"    … and {len(messages) - 3} more")
    print()


# ---------------------------------------------------------------------------
# 8. Top error phrases
# ---------------------------------------------------------------------------

error_msgs = df[df["level"] == "ERROR"]["message"]
phrases = extract_top_error_phrases(error_msgs, top_n=5)
if not phrases.empty:
    print("── Common error phrases ──────────────")
    for _, row in phrases.iterrows():
        print(f"  {row['count']:>3}×  {row['ngram']}")
    print()


# ---------------------------------------------------------------------------
# 9. PII redaction demo
# ---------------------------------------------------------------------------

print("── PII redaction demo ────────────────")
sample_messages = df["message"].dropna().head(5).tolist()
for msg in sample_messages:
    redacted = redact_pii(msg)
    if redacted != msg:
        print(f"  before: {msg[:80]}")
        print(f"  after : {redacted[:80]}")
        print()


# ---------------------------------------------------------------------------
# 10. Sequence mining
# ---------------------------------------------------------------------------

sequences = sequence_mining(df, window_minutes=5, seq_len=3, top_k=5)
if not sequences.empty:
    print("── Top event sequences before errors ─")
    for _, row in sequences.iterrows():
        seq_str = " → ".join(row["sequence"])
        print(f"  {row['count']:>3}×  {seq_str}")
    print()


print("Done.")
