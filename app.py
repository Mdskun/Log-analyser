"""
Professional Log Analyzer
=========================

Main Streamlit application entry point.

Usage:
    streamlit run app.py
"""

import streamlit as st
import pandas as pd

# Local imports
from src.parsers import LogParser
from src.utils import iter_lines, merge_multiline_stack, detect_format, add_enrichments
from src.analytics import module_ranking, hourly_metrics
from src.utils.enrichment import redact_pii

# Tab implementations
from src.ui.tabs import (
    render_charts_tab,
    render_heatmaps_tab,
    render_types_ranking_tab,
    render_clusters_tab,
    render_anomalies_tab,
    render_sequences_tab,
)

# Configure Streamlit page
st.set_page_config(
    page_title="Log Analyzer Pro",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

__version__ = "4.0.0"
__author__ = "Your Team"


def main():
    """Main application entry point."""

    st.title("📊 Log Analyzer Pro")
    st.markdown(f"*Version {__version__}* | Professional log analysis tool")

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")

        max_lines = st.number_input(
            "Max lines to parse (0 = unlimited)",
            min_value=0,
            value=0,
            step=10000,
            help="Limit parsing for faster analysis of large files",
        )

        st.divider()

        st.header("🔐 Privacy")
        do_redact = st.checkbox(
            "Redact PII",
            value=False,
            help="Remove emails, IPs, UUIDs, and tokens from display",
        )

    # File upload
    uploaded_file = st.file_uploader(
        "Upload log file",
        type=["log", "txt", "json", "xml"],
        help="Supported formats: syslog, apache, JSON, Docker, K8s, etc.",
    )

    if uploaded_file is None:
        show_welcome_screen()
        return

    process_log_file(uploaded_file, max_lines, do_redact)


def show_welcome_screen():
    """Display welcome screen with information."""
    col1, col2, col3 = st.columns(3)

    with col1:
        st.info(
            "### 📁 Upload a Log File\n"
            "Supports 10+ formats including Apache, syslog, JSON, Docker, Kubernetes"
        )
    with col2:
        st.success(
            "### 🚀 Fast Analysis\n"
            "Optimized parsers with caching and streaming support"
        )
    with col3:
        st.warning(
            "### 🔐 Privacy First\n"
            "Built-in PII redaction for sensitive data protection"
        )

    st.divider()
    st.subheader("✨ Key Features")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            "**Analysis & Insights**\n"
            "- 📊 Statistical metrics\n"
            "- 🤖 ML-based clustering\n"
            "- 🚨 Anomaly detection\n"
            "- 🧬 Sequence mining\n"
            "- 🗺️ Activity heatmaps"
        )
    with c2:
        st.markdown(
            "**Supported Formats**\n"
            "- Custom structured logs\n"
            "- Syslog & Apache logs\n"
            "- JSON (generic, Docker, K8s)\n"
            "- AWS CloudWatch\n"
            "- GCP Cloud Logging\n"
            "- Windows Event Logs (XML)"
        )

    with st.expander("📖 Quick Start Guide"):
        st.markdown(
            "1. **Upload** your log file using the uploader above\n"
            "2. **Configure** parsing options in the sidebar\n"
            "3. **Explore** the analysis tabs:\n"
            "   - 📋 Data: View parsed logs\n"
            "   - 📈 Charts: Visualize trends\n"
            "   - 🗺️ Heatmaps: Spot patterns\n"
            "   - 🔎 Types: Analyze error rates\n"
            "   - 🤖 Clusters: Group similar errors\n"
            "   - 🚨 Anomalies: Detect spikes\n"
            "   - 🧬 Sequences: Find error patterns\n"
            "   - 📥 Export: Download results"
        )


def process_log_file(uploaded_file, max_lines: int, do_redact: bool):
    """
    Process the uploaded log file end-to-end:
    detect → parse → enrich → (optionally redact) → render tabs.
    """
    # 1. Format detection
    with st.spinner("🔍 Detecting log format…"):
        peek_lines = []
        for i, line in enumerate(iter_lines(uploaded_file)):
            peek_lines.append(line)
            if i >= 50:
                break

        log_format = detect_format(tuple(peek_lines))

        col1, col2 = st.columns([3, 1])
        with col1:
            st.success(f"✅ Detected format: **{log_format}**")
        with col2:
            if st.button("🔄 Change Format"):
                st.info("Manual format selection coming in v4.1")

    # 2. Parse
    with st.spinner("📝 Parsing log file…"):
        try:
            df = _parse_logs(uploaded_file, log_format, max_lines)
            if df.empty:
                st.error("❌ No logs could be parsed. Please check the file format.")
                return
            st.success(f"✅ Parsed {len(df):,} log entries")
        except Exception as e:
            st.error(f"❌ Error parsing file: {e}")
            with st.expander("Error Details"):
                st.exception(e)
            return

    # 3. Enrich
    with st.spinner("✨ Enriching data…"):
        try:
            df = add_enrichments(df)
        except Exception as e:
            st.warning(f"⚠️ Enrichment partially failed: {e}")

    # 4. PII redaction
    if do_redact:
        with st.spinner("🔐 Redacting PII…"):
            df["redacted_message"] = df["message"].apply(redact_pii)

    # 5. Filters + tabs
    render_analysis_tabs(df, do_redact)


def _parse_logs(uploaded_file, log_format: str, max_lines: int) -> pd.DataFrame:
    """Parse the log file and return a DataFrame."""

    def limited_lines():
        for i, line in enumerate(iter_lines(uploaded_file)):
            if max_lines and i >= max_lines:
                break
            yield line

    line_iter = limited_lines()

    structured_formats = {
        "json", "docker_json", "kubernetes_json",
        "cloudwatch_export", "gcp_cloud_logging", "windows_event_xml",
    }
    if log_format not in structured_formats:
        line_iter = merge_multiline_stack(line_iter)

    df = LogParser.parse(line_iter, log_format)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df


def render_analysis_tabs(df: pd.DataFrame, do_redact: bool):
    """Apply sidebar filters, then render all analysis tabs."""
    filtered_df = _apply_sidebar_filters(df)
    display_col = "redacted_message" if do_redact else "message"

    tabs = st.tabs([
        "📋 Data",
        "📈 Charts",
        "🗺️ Heatmaps",
        "🔎 Types & Ranking",
        "🤖 Clusters",
        "🚨 Anomalies",
        "🧬 Sequences",
        "📥 Export",
    ])

    with tabs[0]:
        _render_data_tab(filtered_df, display_col)

    with tabs[1]:
        render_charts_tab(filtered_df)

    with tabs[2]:
        render_heatmaps_tab(filtered_df)

    with tabs[3]:
        render_types_ranking_tab(filtered_df)

    with tabs[4]:
        render_clusters_tab(filtered_df)

    with tabs[5]:
        render_anomalies_tab(filtered_df)

    with tabs[6]:
        render_sequences_tab(filtered_df)

    with tabs[7]:
        _render_export_tab(filtered_df, do_redact)


def _apply_sidebar_filters(df: pd.DataFrame) -> pd.DataFrame:
    """Render sidebar filter widgets and return the filtered DataFrame."""
    with st.sidebar:
        st.divider()
        st.header("🔍 Filters")

        filtered = df.copy()

        # Time range
        if "timestamp" in filtered.columns and filtered["timestamp"].notna().any():
            ts_clean = filtered["timestamp"].dropna()
            if not ts_clean.empty:
                min_time = ts_clean.min().to_pydatetime()
                max_time = ts_clean.max().to_pydatetime()

                time_range = st.slider(
                    "Time Range",
                    min_value=min_time,
                    max_value=max_time,
                    value=(min_time, max_time),
                )
                filtered = filtered[
                    (filtered["timestamp"] >= time_range[0])
                    & (filtered["timestamp"] <= time_range[1])
                ]

        # Log level
        if "level" in filtered.columns:
            all_levels = sorted(filtered["level"].unique().tolist())
            levels_sel = st.multiselect("Log Levels", all_levels)
            if levels_sel:
                filtered = filtered[filtered["level"].isin(levels_sel)]

        # Module
        if "module" in filtered.columns:
            all_modules = sorted(filtered["module"].dropna().unique().tolist())
            modules_sel = st.multiselect("Modules", all_modules)
            if modules_sel:
                filtered = filtered[filtered["module"].isin(modules_sel)]

        # Keyword
        keyword = st.text_input("Keyword Search")
        if keyword:
            filtered = filtered[
                filtered["message"]
                .astype(str)
                .str.contains(keyword, case=False, na=False)
            ]

        st.caption(f"Showing {len(filtered):,} of {len(df):,} entries")

    return filtered


def _render_data_tab(df: pd.DataFrame, display_col: str):
    """Paginated data viewer tab."""
    st.subheader("📋 Parsed Log Data")

    page_size = st.number_input("Rows per page", 50, 5000, 200, 50)
    total_pages = max(1, (len(df) + page_size - 1) // page_size)
    page = st.number_input("Page", 1, int(total_pages), 1)

    start = (page - 1) * page_size
    end = min(page * page_size, len(df))

    st.caption(f"Showing rows {start + 1}–{end} of {len(df):,}")

    preferred_cols = [
        "timestamp", "level", "module", "ip", "status_code",
        "request_type", "request_path", "response_time_ms",
        "user_id", "ua_browser", "ua_os", "ua_device", display_col,
    ]
    preferred_cols = [c for c in preferred_cols if c in df.columns]
    other_cols = [c for c in df.columns if c not in preferred_cols]

    st.dataframe(df[preferred_cols + other_cols].iloc[start:end], use_container_width=True)


def _render_export_tab(df: pd.DataFrame, redact: bool):
    """Export tab with CSV and JSON download buttons."""
    st.subheader("📥 Export Data")

    export_df = df.copy()
    if redact and "message" in export_df.columns:
        export_df["message"] = export_df["message"].apply(redact_pii)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "📥 Download CSV",
            export_df.to_csv(index=False),
            "log_analysis.csv",
            mime="text/csv",
        )
    with col2:
        st.download_button(
            "📥 Download JSON",
            export_df.to_json(orient="records", lines=True),
            "log_analysis.json",
            mime="application/json",
        )

    st.info("💡 Tip: Use sidebar filters to export only the data you need.")


if __name__ == "__main__":
    main()
