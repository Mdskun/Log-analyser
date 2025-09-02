import os
import re
import json
import pandas as pd
from datetime import datetime
import streamlit as st
import altair as alt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import CountVectorizer

# =============================
#           Parsers
# =============================
# Log Format Detection (extended)

def detect_format(sample_lines):
    patterns = {
        # Existing
        "custom": r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[\w+\] \[.*?\] .*",
        "syslog": r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} .+",
        "apache": r"\d+\.\d+\.\d+\.\d+ - - \[.*?\] \".*?\" \d{3} \d+",
        "json": r"^\{.*\}$",
        # New formats
        "docker_json": r"^\{.*\"log\":.*\"time\":.*\}$",
        "kubernetes_json": r"^\{.*\"kubernetes\"\s*:\s*\{.*\}.*\}$",
        "cloudwatch_export": r"^\{.*\"logGroup\".*\"logStream\".*\"message\".*\}$",
        "gcp_cloud_logging": r"^\{.*(\"textPayload\"|\"jsonPayload\"|\"protoPayload\").*\}$",
        "windows_event_xml": r"^\s*<Event[ >].*"
    }
    for fmt, pattern in patterns.items():
        for line in sample_lines:
            if re.match(pattern, line.strip()):
                return fmt
    return "generic"

# -------- Pre-processing for multiline stacks (non-JSON formats)

def merge_multiline_stack(iterable):
    """Merge obvious stack trace continuation lines into the previous line's message.
    Heuristics: lines starting with whitespace, 'at ', '... ', 'Caused by:', 'Traceback', or Python 'File "", line'.
    We only call this for non-JSON/non-XML formats to avoid breaking structured logs.
    """
    ts_start = re.compile(r"^(\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d+\.\d+\.\d+\.\d+ - - \[|<Event|\{)")
    cont = re.compile(r"^(\s+|at\s|\.\.\.|Caused by:|Traceback|File \".+\", line \d+)")
    buf = []
    for raw in iterable:
        line = raw.rstrip("\n")
        if ts_start.search(line):
            if buf:
                yield "\n".join(buf)
                buf = []
            buf = [line]
        elif cont.search(line):
            if buf:
                buf.append(line)
            else:
                buf = [line]
        else:
            if buf:
                buf.append(line)
            else:
                buf = [line]
    if buf:
        yield "\n".join(buf)

# -------- Existing analyzers

def analyze_custom(lines):
    pattern = r"\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)"
    fmt = "%Y-%m-%d %H:%M:%S"
    data = []
    for line in lines:
        m = re.match(pattern, line)
        if m:
            try:
                ts = datetime.strptime(m.group(1), fmt)
                level, module, msg = m.group(2), m.group(3), m.group(4)
                data.append({"timestamp": ts, "level": level, "module": module, "message": msg})
            except Exception:
                continue
    return pd.DataFrame(data)


def analyze_json(lines):
    rows = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append({
            "timestamp": obj.get("timestamp") or obj.get("time") or obj.get("@timestamp"),
            "level": obj.get("level") or obj.get("severity") or obj.get("logLevel") or "UNKNOWN",
            "module": obj.get("module") or obj.get("logger") or obj.get("logName") or obj.get("logStream") or "unknown",
            "message": obj.get("message") or obj.get("msg") or obj.get("log") or obj.get("textPayload") or "",
            "ip": obj.get("ip") or obj.get("client_ip")
        })
    return pd.DataFrame(rows)


def analyze_syslog(lines):
    data = []
    for line in lines:
        m = re.match(r"^(\w{3} +\d+ \d{2}:\d{2}:\d{2}) (\S+) (.+?): (.*)", line)
        if m:
            ts, host, module, msg = m.groups()
            data.append({"timestamp": ts, "level": "INFO", "module": module, "message": msg, "ip": host})
    return pd.DataFrame(data)


def analyze_apache(lines):
    data = []
    for line in lines:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?\"(.*?)\" (\d{3})", line)
        if m:
            ip, ts, req, code = m.groups()
            data.append({"timestamp": ts, "level": code, "module": ip, "message": req, "ip": ip})
    return pd.DataFrame(data)


def analyze_generic(lines):
    data = []
    for line in lines:
        ts_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2})", line)
        level_match = re.search(r"\b(INFO|ERROR|WARN|WARNING|DEBUG|CRITICAL)\b", line, re.IGNORECASE)
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        ts = ts_match.group(1) if ts_match else None
        level = level_match.group(1).upper() if level_match else "UNKNOWN"
        ip = ip_match.group(1) if ip_match else None
        msg = line.strip()
        data.append({"timestamp": ts, "level": level, "module": "unknown", "message": msg, "ip": ip})
    return pd.DataFrame(data)

# -------- New analyzers

def analyze_docker_json(lines):
    """Docker JSON file driver: {"log": "...", "time": "...", "stream": "stdout"} per line"""
    rows = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append({
            "timestamp": obj.get("time"),
            "level": obj.get("level") or "INFO",
            "module": obj.get("container_name") or obj.get("source") or "docker",
            "message": (obj.get("log") or "").rstrip(),
            "ip": None
        })
    return pd.DataFrame(rows)


def analyze_kubernetes_json(lines):
    """Common k8s JSON format from container runtime/log router with kubernetes metadata"""
    rows = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        k8s = obj.get("kubernetes", {}) if isinstance(obj, dict) else {}
        module = "/".join(filter(None, [k8s.get("namespace_name"), k8s.get("pod_name"), k8s.get("container_name")])) or "kubernetes"
        rows.append({
            "timestamp": obj.get("time") or obj.get("timestamp"),
            "level": obj.get("level") or obj.get("severity") or "INFO",
            "module": module,
            "message": obj.get("log") or obj.get("message") or "",
            "ip": None
        })
    return pd.DataFrame(rows)


def analyze_cloudwatch(lines):
    """AWS CloudWatch Logs export JSON: has logGroup, logStream, message, timestamp"""
    rows = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append({
            "timestamp": obj.get("timestamp"),
            "level": obj.get("level") or obj.get("severity") or "INFO",
            "module": obj.get("logGroup") or obj.get("logStream") or "cloudwatch",
            "message": obj.get("message") or obj.get("@message") or "",
            "ip": None
        })
    return pd.DataFrame(rows)


def analyze_gcp_cloud_logging(lines):
    """GCP Cloud Logging export JSON: textPayload / jsonPayload / protoPayload"""
    rows = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = obj.get("textPayload")
        if not msg and isinstance(obj.get("jsonPayload"), dict):
            msg = json.dumps(obj.get("jsonPayload"), ensure_ascii=False)
        if not msg and isinstance(obj.get("protoPayload"), dict):
            msg = json.dumps(obj.get("protoPayload"), ensure_ascii=False)
        rows.append({
            "timestamp": obj.get("timestamp") or obj.get("receiveTimestamp"),
            "level": obj.get("severity") or "INFO",
            "module": (obj.get("logName") or "gcp").split("/")[-1],
            "message": msg or "",
            "ip": None
        })
    return pd.DataFrame(rows)


def analyze_windows_event_xml(lines):
    """Very light XML support for exported Windows EventLog XML (not .evtx). Parses minimal fields."""
    rows = []
    # Coalesce lines into events
    buf = []
    def flush_event(event_text):
        if not event_text:
            return
        # Minimal extraction via regex to avoid XML deps
        ts = re.search(r"<TimeCreated[^>]*SystemTime=\"([^\"]+)\"", event_text)
        level = re.search(r"<Level>(\d+)</Level>", event_text)
        provider = re.search(r"<Provider[^>]*Name=\"([^\"]+)\"", event_text)
        msg = re.search(r"<Data>(.*?)</Data>", event_text, re.DOTALL)
        rows.append({
            "timestamp": ts.group(1) if ts else None,
            "level": level.group(1) if level else "INFO",
            "module": provider.group(1) if provider else "WindowsEvent",
            "message": (msg.group(1).strip() if msg else "").replace("\n", " "),
            "ip": None
        })
    for line in lines:
        if "<Event" in line:
            buf = [line]
        elif "</Event>" in line:
            buf.append(line)
            flush_event("\n".join(buf))
            buf = []
        else:
            if buf:
                buf.append(line)
    return pd.DataFrame(rows)

# =============================
#        ML & Analytics Utils
# =============================

def cluster_errors(df, n_clusters=5):
    if "level" not in df.columns:
        return []
    error_msgs = df[df["level"].astype(str).str.upper() == "ERROR"]["message"].fillna("")
    if len(error_msgs) < 2:
        return []
    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(error_msgs)
    model = KMeans(n_clusters=min(n_clusters, len(error_msgs)), random_state=42)
    labels = model.fit_predict(X)
    return list(zip(error_msgs, labels))


def extract_top_error_phrases(messages, top_n=10):
    messages = [m for m in messages.fillna("") if m]
    if len(messages) == 0:
        return pd.DataFrame(columns=["ngram", "count"])
    vectorizer = CountVectorizer(ngram_range=(2, 3), stop_words="english", max_features=2000)
    X = vectorizer.fit_transform(messages)
    freqs = X.sum(axis=0).A1
    terms = vectorizer.get_feature_names_out()
    freq_df = pd.DataFrame({"ngram": terms, "count": freqs})
    return freq_df.sort_values("count", ascending=False).head(top_n)

# ----- Line Type Classification & Rankings -----

LINE_TYPE_PATTERNS = [
    ("HTTP_ACCESS", re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b .* HTTP/\d", re.I)),
    ("EXCEPTION", re.compile(r"Traceback|Exception:|Error:|Caused by:|\bat\s+\w+\.", re.I)),
    ("DB_ERROR", re.compile(r"SQLSTATE|ORA-\d+|psql:|Sequelize|MongoError|jdbc|Deadlock", re.I)),
    ("TIMEOUT", re.compile(r"timed? out|timeout|deadline exceeded", re.I)),
    ("AUTH", re.compile(r"unauthorized|forbidden|invalid token|auth|login failed", re.I)),
    ("NETWORK", re.compile(r"connection (reset|refused|closed)|ECONN|socket|TLS|SSL", re.I)),
    ("RESOURCE", re.compile(r"out of memory|OOM|disk\s(full|quota)|cpu (throttle|limit)", re.I)),
    ("CONFIG", re.compile(r"config|configuration|env var|missing key", re.I)),
    ("STARTUP_SHUTDOWN", re.compile(r"(service|server) (starting|started|stopping|stopped)", re.I)),
    ("GC", re.compile(r"GC \(|Garbage Collector|Allocation Failure", re.I)),
]

HTTP_PATH_RE = re.compile(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\"]+)")
HTTP_STATUS_RE = re.compile(r"\s(\d{3})(?:\s|$)")


def detect_line_type(msg: str) -> str:
    if not isinstance(msg, str):
        return "UNKNOWN"
    for t, rx in LINE_TYPE_PATTERNS:
        if rx.search(msg):
            return t
    return "OTHER"


def add_line_types(df: pd.DataFrame) -> pd.DataFrame:
    if "message" in df.columns:
        df["line_type"] = df["message"].map(detect_line_type)
    else:
        df["line_type"] = "UNKNOWN"
    return df


def module_ranking(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    g = df.groupby("module", dropna=False)
    out = g.agg(
        total=("message", "count"),
        errors=("level", lambda s: (s.astype(str).str.upper() == "ERROR").sum()),
        warns=("level", lambda s: (s.astype(str).str.upper().isin(["WARN", "WARNING"]).sum())),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max")
    ).reset_index()
    out["error_rate"] = (out["errors"] / out["total"]).round(3)
    if "line_type" in df.columns:
        types = df.pivot_table(index="module", columns="line_type", values="message", aggfunc="count", fill_value=0)
        out = out.merge(types.reset_index(), on="module", how="left")
    return out.sort_values(["errors", "error_rate", "total"], ascending=[False, False, False])


def http_stats(df: pd.DataFrame):
    if df.empty:
        return pd.DataFrame(), pd.Series(dtype=int)
    http_df = df[df["message"].astype(str).str.contains("HTTP/", na=False)].copy()
    if http_df.empty:
        return pd.DataFrame(), pd.Series(dtype=int)
    http_df["path"] = http_df["message"].str.extract(HTTP_PATH_RE)
    # status code: prefer numeric level if looks like 3 digits, else extract from message
    http_df["status"] = (
        http_df["level"].astype(str).where(http_df["level"].astype(str).str.match(r"^\d{3}$"))
        .fillna(http_df["message"].str.extract(HTTP_STATUS_RE)[0])
    )
    top_paths = http_df["path"].value_counts().head(20)
    status_dist = http_df["status"].value_counts().sort_index()
    return top_paths, status_dist

# =============================
#       Chunked Reading
# =============================

def iter_lines(uploaded_file, encoding="utf-8", errors="ignore"):
    """Generator that decodes line-by-line without loading the whole file in memory."""
    uploaded_file.seek(0)
    for bline in uploaded_file:
        try:
            yield bline.decode(encoding, errors=errors).rstrip("\n")
        except Exception:
            continue

# =============================
#         Streamlit App
# =============================

st.title("📊 Advanced Log File Analyzer (Pro)")

# Scalability controls
st.sidebar.header("⚙️ Ingestion Settings")
max_lines = st.sidebar.number_input("Max lines to parse (0 = no cap)", min_value=0, value=0, step=10000)

uploaded_file = st.file_uploader("Upload a log file", type=["log", "txt", "json", "xml"])

if uploaded_file is not None:
    # Peek at first N lines for format detection
    peek_lines = []
    for i, line in enumerate(iter_lines(uploaded_file)):
        peek_lines.append(line)
        if i >= 50:
            break
    log_format = detect_format(peek_lines)
    st.write(f"**Detected format:** {log_format}")

    # Choose analyzer
    analyzers = {
        "custom": analyze_custom,
        "json": analyze_json,
        "syslog": analyze_syslog,
        "apache": analyze_apache,
        "docker_json": analyze_docker_json,
        "kubernetes_json": analyze_kubernetes_json,
        "cloudwatch_export": analyze_cloudwatch,
        "gcp_cloud_logging": analyze_gcp_cloud_logging,
        "windows_event_xml": analyze_windows_event_xml,
        "generic": analyze_generic,
    }
    analyzer = analyzers.get(log_format, analyze_generic)

    # Build a line iterator again (reset pointer); merge stacks for non-structured formats
    def limited_lines():
        for i, line in enumerate(iter_lines(uploaded_file)):
            if max_lines and i >= max_lines:
                break
            yield line

    line_iter = limited_lines()
    if log_format not in {"json", "docker_json", "kubernetes_json", "cloudwatch_export", "gcp_cloud_logging", "windows_event_xml"}:
        line_iter = merge_multiline_stack(line_iter)

    df = analyzer(line_iter)

    # Normalize timestamps
    if "timestamp" in df.columns:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        except Exception:
            pass

    # Enrich with line types & module rankings
    df = add_line_types(df)

    # ---------------- Dashboard Tabs ----------------
    tab_data, tab_charts, tab_heat, tab_types, tab_cluster, tab_export = st.tabs([
        "📋 Data", "📈 Charts", "🗺️ Heatmaps", "🔎 Types & Ranking", "🤖 Clusters", "📥 Export"
    ])

    # ===== Sidebar Filters (show-all when none selected) =====
    st.sidebar.header("🔍 Filters")
    # Time range
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        ts_clean = df["timestamp"].dropna()
        min_time, max_time = ts_clean.min(), ts_clean.max()
        if pd.notna(min_time) and pd.notna(max_time):
            time_range = st.sidebar.slider(
                "Time Range",
                min_value=min_time.to_pydatetime(),
                max_value=max_time.to_pydatetime(),
                value=(min_time.to_pydatetime(), max_time.to_pydatetime())
            )
            df = df[(df["timestamp"] >= time_range[0]) & (df["timestamp"] <= time_range[1])]

    # Levels
    if "level" in df.columns:
        all_levels = list(pd.unique(df["level"]))
        levels_sel = st.sidebar.multiselect("Log Levels", all_levels, default=[])
        if levels_sel:
            df = df[df["level"].isin(levels_sel)]

    # Modules
    if "module" in df.columns:
        all_modules = list(pd.unique(df["module"]))
        modules_sel = st.sidebar.multiselect("Modules", all_modules, default=[])
        if modules_sel:
            df = df[df["module"].isin(modules_sel)]

    # IPs
    if "ip" in df.columns and df["ip"].notna().any():
        all_ips = list(pd.unique(df["ip"].dropna()))
        ips_sel = st.sidebar.multiselect("IP Addresses", all_ips, default=[])
        if ips_sel:
            df = df[df["ip"].isin(ips_sel)]

    # Keyword
    keyword = st.sidebar.text_input("Keyword contains…")
    if keyword:
        df = df[df["message"].astype(str).str.contains(keyword, case=False, na=False)]

    # ===== Data Tab with Pagination =====
    with tab_data:
        st.subheader("Parsed Log Data")
        total_rows = len(df)
        page_size = st.number_input("Rows per page", min_value=50, max_value=5000, value=200, step=50)
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        page = st.number_input("Page", min_value=1, max_value=int(total_pages), value=1)
        start, end = (page - 1) * page_size, min(page * page_size, total_rows)
        st.caption(f"Showing rows {start+1}-{end} of {total_rows}")
        st.dataframe(df.iloc[start:end])

    # ===== Charts Tab =====
    with tab_charts:
        if "level" in df.columns:
            st.subheader("Log Level Distribution")
            st.bar_chart(df["level"].value_counts())
        if "timestamp" in df.columns and df["timestamp"].notna().any():
            st.subheader("Logs Over Time (Total)")
            ts_counts = df.set_index("timestamp").resample("1H").size().reset_index(name="count")
            st.line_chart(ts_counts.set_index("timestamp")["count"])
            if "level" in df.columns:
                st.subheader("Log Level Timeline (stacked area)")
                timeline = df.groupby([pd.Grouper(key="timestamp", freq="1H"), "level"]).size().reset_index(name="count")
                chart = alt.Chart(timeline).mark_area().encode(
                    x="timestamp:T",
                    y="count:Q",
                    color="level:N"
                )
                st.altair_chart(chart, use_container_width=True)

    # ===== Heatmaps Tab =====
    with tab_heat:
        if "timestamp" in df.columns and df["timestamp"].notna().any():
            st.subheader("Activity Heatmap (Hour × Day)")
            heatmap_df = df.copy()
            heatmap_df["hour"] = heatmap_df["timestamp"].dt.hour
            heatmap_df["day"] = heatmap_df["timestamp"].dt.day_name()
            pivot = heatmap_df.pivot_table(index="day", columns="hour", values="message", aggfunc="count", fill_value=0)
            st.dataframe(pivot)
        if "module" in df.columns:
            st.subheader("Error Density by Module")
            module_errs = df[df["level"].astype(str).str.upper() == "ERROR"]["module"].value_counts()
            st.bar_chart(module_errs)

    # ===== Types & Ranking Tab =====
    with tab_types:
        st.subheader("Line Type Distribution")
        if "line_type" in df.columns:
            st.bar_chart(df["line_type"].value_counts())
        
        st.subheader("Module Ranking (Errors, Error Rate, Volume)")
        rank_df = module_ranking(df)
        if not rank_df.empty:
            st.dataframe(rank_df)
            # Top offenders by error rate with minimum volume
            min_vol = st.number_input("Min rows per module for error-rate chart", min_value=1, value=20)
            top_rate = rank_df[rank_df["total"] >= min_vol].nlargest(10, "error_rate")
            if not top_rate.empty:
                st.bar_chart(top_rate.set_index("module")["error_rate"])
        else:
            st.info("No module stats available.")

        st.subheader("HTTP Stats (if present)")
        top_paths, status_dist = http_stats(df)
        if not top_paths.empty:
            st.write("Top paths")
            st.dataframe(top_paths.to_frame("count"))
        if not status_dist.empty:
            st.write("Status code distribution")
            st.bar_chart(status_dist)

    # ===== Clusters Tab =====
    with tab_cluster:
        st.subheader("Error Clusters")
        clusters = cluster_errors(df)
        if clusters:
            cluster_df = pd.DataFrame(clusters, columns=["message", "cluster"])
            st.dataframe(cluster_df)
            st.subheader("Frequent Error Phrases (n-grams)")
            errors_only = df[df["level"].astype(str).str.upper() == "ERROR"]
            top_phrases = extract_top_error_phrases(errors_only["message"])
            if not top_phrases.empty:
                st.dataframe(top_phrases)
            else:
                st.info("Not enough error messages for phrase extraction.")
        else:
            st.info("No sufficient error messages to cluster.")

    # ===== Export Tab =====
    with tab_export:
        st.subheader("Export Data")
        st.download_button("Download CSV", df.to_csv(index=False), "log_analysis.csv")
        st.download_button("Download JSON", df.to_json(orient='records', lines=True), "log_analysis.json")

    # Helpful note for Windows .evtx
    st.caption("Note: Parsing binary .evtx requires extra packages (e.g., python-evtx). This app supports XML exports.")
