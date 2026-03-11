"""
Anomalies Tab
=============
Renders the Anomalies detection tab in the Streamlit UI.
"""

import pandas as pd
import streamlit as st

from src.analytics import hourly_metrics


def render_anomalies_tab(df: pd.DataFrame) -> None:
    """
    Render the Anomalies tab showing hourly metrics, z-score charts,
    and detected spike events.

    Args:
        df: Filtered, enriched log DataFrame
    """
    st.subheader("🚨 Anomaly Detection")

    if df.empty:
        st.info("No data available for the current filter selection.")
        return

    if "timestamp" not in df.columns or df["timestamp"].isna().all():
        st.info("Anomaly detection requires timestamp data.")
        return

    with st.spinner("Computing hourly metrics…"):
        metrics = hourly_metrics(df)

    if metrics.empty:
        st.info("Not enough timestamped entries for anomaly detection.")
        return

    # Summary metrics
    spike_count = int(metrics["spike"].sum())
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Hours", len(metrics))
    col2.metric("Spike Hours Detected", spike_count, delta_color="inverse")
    col3.metric(
        "Peak Error Ratio",
        f"{metrics['error_ratio'].max():.1%}",
    )

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.write("**Error Ratio Over Time**")
        st.line_chart(metrics.set_index("timestamp")["error_ratio"])

    with col_b:
        st.write("**Z-Score (Errors)**")
        st.line_chart(metrics.set_index("timestamp")["z_errors"].fillna(0))

    st.write("**Log Volume Over Time**")
    st.line_chart(metrics.set_index("timestamp")[["count", "count_ma"]].fillna(0))

    # Spike detail table
    spikes = metrics[metrics["spike"]]
    if not spikes.empty:
        st.warning(f"⚠️ {len(spikes)} anomalous hour(s) detected")
        st.dataframe(
            spikes[["timestamp", "count", "errors", "error_ratio", "z_count", "z_errors"]]
            .sort_values("timestamp", ascending=False),
            use_container_width=True,
        )
    else:
        st.success("✅ No anomalous hours detected in the selected time range.")

    with st.expander("📋 Full Hourly Metrics Table"):
        st.dataframe(
            metrics.sort_values("timestamp", ascending=False),
            use_container_width=True,
        )
