"""
Clusters Tab
============
Renders the Clusters analysis tab in the Streamlit UI.
"""

import pandas as pd
import streamlit as st

from src.analytics import cluster_errors, extract_top_error_phrases


def render_clusters_tab(df: pd.DataFrame) -> None:
    """
    Render the Clusters tab showing KMeans-grouped error messages
    and the most frequent error n-gram phrases.

    Args:
        df: Filtered, enriched log DataFrame
    """
    st.subheader("🤖 Error Clustering")

    if df.empty:
        st.info("No data available for the current filter selection.")
        return

    error_count = (
        df["level"].astype(str).str.upper().eq("ERROR").sum()
        if "level" in df.columns
        else 0
    )

    if error_count < 2:
        st.info("Not enough error messages to cluster (need at least 2).")
        return

    n_clusters = st.slider("Number of clusters", min_value=2, max_value=10, value=5)

    with st.spinner("Clustering errors…"):
        clusters = cluster_errors(df, n_clusters)

    if not clusters:
        st.info("Clustering produced no results.")
        return

    cluster_df = pd.DataFrame(clusters, columns=["message", "cluster"])
    cluster_df["cluster"] = cluster_df["cluster"].astype(str)

    st.write(f"Clustered **{len(cluster_df)}** error messages into **{n_clusters}** groups.")

    # Per-cluster breakdown
    for label in sorted(cluster_df["cluster"].unique(), key=int):
        group = cluster_df[cluster_df["cluster"] == label]
        with st.expander(f"Cluster {label}  ({len(group)} messages)"):
            st.dataframe(group["message"].reset_index(drop=True), use_container_width=True)

    st.divider()
    st.subheader("💬 Frequent Error Phrases (n-grams)")

    errors_only = df[df["level"].astype(str).str.upper() == "ERROR"]
    top_n = st.slider("Top N phrases", min_value=5, max_value=30, value=10)

    with st.spinner("Extracting phrases…"):
        top_phrases = extract_top_error_phrases(errors_only["message"], top_n=top_n)

    if not top_phrases.empty:
        st.bar_chart(top_phrases.set_index("ngram")["count"])
        st.dataframe(top_phrases, use_container_width=True)
    else:
        st.info("Not enough error messages for phrase extraction.")
