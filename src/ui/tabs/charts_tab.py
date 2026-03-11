"""
Charts Tab
==========
Renders the Charts analysis tab in the Streamlit UI.
"""

import pandas as pd
import streamlit as st
import altair as alt


def render_charts_tab(df: pd.DataFrame) -> None:
    """
    Render the Charts tab with level distribution, status codes,
    time-series volume, log-level timeline, and response-time plot.

    Args:
        df: Filtered, enriched log DataFrame
    """
    st.subheader("📈 Log Analytics Charts")

    if df.empty:
        st.info("No data available for the current filter selection.")
        return

    col1, col2 = st.columns(2)

    with col1:
        if "level" in df.columns:
            st.write("**Log Level Distribution**")
            st.bar_chart(df["level"].value_counts())

    with col2:
        if "status_code" in df.columns and df["status_code"].notna().any():
            st.write("**HTTP Status Distribution**")
            st.bar_chart(df["status_code"].value_counts().sort_index())

    # Time-series volume
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        st.subheader("Logs Over Time (hourly)")
        ts_counts = (
            df.set_index("timestamp")
            .resample("1H")
            .size()
            .reset_index(name="count")
        )
        st.line_chart(ts_counts.set_index("timestamp")["count"])

        # Stacked area chart by level
        if "level" in df.columns:
            st.subheader("Log Level Timeline")
            timeline = (
                df.groupby([pd.Grouper(key="timestamp", freq="1H"), "level"])
                .size()
                .reset_index(name="count")
            )
            chart = (
                alt.Chart(timeline)
                .mark_area()
                .encode(
                    x=alt.X("timestamp:T", title="Time"),
                    y=alt.Y("count:Q", title="Count"),
                    color=alt.Color("level:N", title="Level"),
                    tooltip=["timestamp:T", "level:N", "count:Q"],
                )
                .properties(height=300)
            )
            st.altair_chart(chart, use_container_width=True)

    # Response time
    if "response_time_ms" in df.columns and df["response_time_ms"].notna().any():
        st.subheader("Response Time (ms) Over Time")
        rt_df = df[["timestamp", "response_time_ms"]].dropna()
        st.line_chart(rt_df.set_index("timestamp")["response_time_ms"])

    # Request method distribution
    if "request_type" in df.columns and df["request_type"].notna().any():
        st.subheader("HTTP Method Distribution")
        st.bar_chart(df["request_type"].value_counts())
