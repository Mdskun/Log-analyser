"""
Sequences Tab
=============
Renders the Sequence Mining tab in the Streamlit UI.
"""

import pandas as pd
import streamlit as st

from src.analytics import sequence_mining


def render_sequences_tab(df: pd.DataFrame) -> None:
    """
    Render the Sequences tab showing common event sequences that
    precede error log entries.

    Args:
        df: Filtered, enriched log DataFrame
    """
    st.subheader("🧬 Sequence Mining")
    st.caption(
        "Finds recurring patterns of event types that appear before error entries."
    )

    if df.empty:
        st.info("No data available for the current filter selection.")
        return

    if "timestamp" not in df.columns or df["timestamp"].isna().all():
        st.info("Sequence mining requires timestamp data.")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        window = st.number_input("Look-back window (minutes)", 1, 120, 5)
    with col2:
        seq_len = st.number_input("Max sequence length", 2, 6, 3)
    with col3:
        top_k = st.number_input("Top-K sequences", 5, 50, 15)

    with st.spinner("Mining sequences…"):
        seq_df = sequence_mining(
            df,
            window_minutes=int(window),
            seq_len=int(seq_len),
            top_k=int(top_k),
        )

    if seq_df.empty:
        st.info(
            "No sequences found. Try increasing the look-back window "
            "or ensure there are errors with prior context."
        )
        return

    st.write(f"Found **{len(seq_df)}** recurring sequences.")

    # Format sequence tuples for display
    display_df = seq_df.copy()
    display_df["sequence"] = display_df["sequence"].apply(
        lambda s: " → ".join(s) if isinstance(s, tuple) else str(s)
    )

    st.bar_chart(display_df.set_index("sequence")["count"])
    st.dataframe(display_df, use_container_width=True)
