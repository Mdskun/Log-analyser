"""
Types & Ranking Tab
===================
Renders the Types & Ranking analysis tab in the Streamlit UI.
"""

import pandas as pd
import streamlit as st

from src.analytics import module_ranking


def render_types_ranking_tab(df: pd.DataFrame) -> None:
    """
    Render the Types & Ranking tab showing line-type distribution
    and module error ranking.

    Args:
        df: Filtered, enriched log DataFrame
    """
    st.subheader("🔎 Line Type Distribution")

    if df.empty:
        st.info("No data available for the current filter selection.")
        return

    if "line_type" in df.columns:
        type_counts = df["line_type"].value_counts()
        col1, col2 = st.columns([2, 1])
        with col1:
            st.bar_chart(type_counts)
        with col2:
            st.dataframe(
                type_counts.rename_axis("Type").reset_index(name="Count"),
                use_container_width=True,
            )
    else:
        st.info("Line type enrichment not available.")

    st.divider()
    st.subheader("📊 Module Ranking")

    rank_df = module_ranking(df)

    if rank_df.empty:
        st.info("No module statistics available.")
        return

    st.dataframe(rank_df, use_container_width=True)

    # Error-rate bar chart for modules with sufficient volume
    min_vol = st.number_input(
        "Min log entries to include in error-rate chart",
        min_value=1,
        value=20,
        step=5,
    )
    top_rate = rank_df[rank_df["total"] >= min_vol].nlargest(15, "error_rate")

    if not top_rate.empty:
        st.write("**Top 15 Modules by Error Rate**")
        st.bar_chart(top_rate.set_index("module")["error_rate"])
    else:
        st.info(f"No modules with ≥ {min_vol} entries found.")
