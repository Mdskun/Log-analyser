"""
Heatmaps Tab
============
Renders the Heatmaps analysis tab in the Streamlit UI.
"""

import pandas as pd
import streamlit as st
import altair as alt


def render_heatmaps_tab(df: pd.DataFrame) -> None:
    """
    Render the Heatmaps tab with day-of-week/hour activity heatmap
    and error density by module.

    Args:
        df: Filtered, enriched log DataFrame
    """
    st.subheader("🗺️ Activity Heatmaps")

    if df.empty:
        st.info("No data available for the current filter selection.")
        return

    # Day × Hour heatmap
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        hm = df[df["timestamp"].notna()].copy()
        hm["hour"] = hm["timestamp"].dt.hour
        hm["day"] = hm["timestamp"].dt.day_name()

        DAY_ORDER = [
            "Monday", "Tuesday", "Wednesday",
            "Thursday", "Friday", "Saturday", "Sunday",
        ]
        hm["day"] = pd.Categorical(hm["day"], categories=DAY_ORDER, ordered=True)

        pivot = (
            hm.groupby(["day", "hour"])
            .size()
            .reset_index(name="count")
        )

        st.write("**Activity by Hour and Day of Week**")
        heatmap_chart = (
            alt.Chart(pivot)
            .mark_rect()
            .encode(
                x=alt.X("hour:O", title="Hour of Day"),
                y=alt.Y("day:O", title="Day", sort=DAY_ORDER),
                color=alt.Color(
                    "count:Q",
                    scale=alt.Scale(scheme="blues"),
                    title="Log Count",
                ),
                tooltip=["day:O", "hour:O", "count:Q"],
            )
            .properties(height=250)
        )
        st.altair_chart(heatmap_chart, use_container_width=True)

        # Error-only heatmap
        if "level" in df.columns:
            err_hm = hm[hm["level"].astype(str).str.upper() == "ERROR"]
            if not err_hm.empty:
                err_pivot = (
                    err_hm.groupby(["day", "hour"])
                    .size()
                    .reset_index(name="count")
                )
                st.write("**Error Activity by Hour and Day**")
                err_chart = (
                    alt.Chart(err_pivot)
                    .mark_rect()
                    .encode(
                        x=alt.X("hour:O", title="Hour of Day"),
                        y=alt.Y("day:O", title="Day", sort=DAY_ORDER),
                        color=alt.Color(
                            "count:Q",
                            scale=alt.Scale(scheme="reds"),
                            title="Error Count",
                        ),
                        tooltip=["day:O", "hour:O", "count:Q"],
                    )
                    .properties(height=250)
                )
                st.altair_chart(err_chart, use_container_width=True)
    else:
        st.info("No timestamp data available for heatmaps.")

    # Error density by module
    if "module" in df.columns and "level" in df.columns:
        st.subheader("Error Density by Module (Top 20)")
        module_errs = (
            df[df["level"].astype(str).str.upper() == "ERROR"]["module"]
            .value_counts()
            .head(20)
        )
        if not module_errs.empty:
            st.bar_chart(module_errs)
        else:
            st.info("No error entries found.")
