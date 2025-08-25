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

# === Log Format Detection ===
def detect_format(lines):
    patterns = {
        "custom": r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[\w+\] \[.*?\] .*",
        "syslog": r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} .+",
        "apache": r"\d+\.\d+\.\d+\.\d+ - - \[.*?\] \".*?\" \d{3} \d+",
        "json": r"^\{.*\"timestamp\".*\}$"
    }
    for fmt, pattern in patterns.items():
        for line in lines:
            if re.match(pattern, line.strip()):
                return fmt
    return "generic"

# === Parsing and Analysis Functions ===
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
            except:
                continue
    return pd.DataFrame(data)

def analyze_json(lines):
    data = []
    for line in lines:
        try:
            obj = json.loads(line)
            data.append({
                "timestamp": obj.get("timestamp"),
                "level": obj.get("level", "UNKNOWN"),
                "module": obj.get("module", "unknown"),
                "message": obj.get("message", ""),
                "ip": obj.get("ip")
            })
        except json.JSONDecodeError:
            continue
    return pd.DataFrame(data)

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

# === Clustering Errors ===
def cluster_errors(df, n_clusters=5):
    if "level" not in df.columns:
        return []
    error_msgs = df[df["level"].astype(str).str.upper() == "ERROR"]["message"]
    if len(error_msgs) < 2:
        return []
    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(error_msgs)
    model = KMeans(n_clusters=min(n_clusters, len(error_msgs)), random_state=42)
    labels = model.fit_predict(X)
    clustered = list(zip(error_msgs, labels))
    return clustered

# === Top Error Types via TF-IDF n-grams ===
def extract_top_error_phrases(messages, top_n=10):
    if len(messages) == 0:
        return []
    vectorizer = CountVectorizer(ngram_range=(2,3), stop_words="english", max_features=1000)
    X = vectorizer.fit_transform(messages)
    freqs = X.sum(axis=0).A1
    terms = vectorizer.get_feature_names_out()
    freq_df = pd.DataFrame({"ngram": terms, "count": freqs})
    return freq_df.sort_values("count", ascending=False).head(top_n)

# === Streamlit App ===
st.title("📊 Advanced Log File Analyzer")

uploaded_file = st.file_uploader("Upload a log file", type=["log", "txt"])

if uploaded_file is not None:
    lines = uploaded_file.read().decode("utf-8", errors="ignore").splitlines()
    log_format = detect_format(lines[:10])
    st.write(f"**Detected format:** {log_format}")

    if log_format == "custom":
        df = analyze_custom(lines)
    elif log_format == "json":
        df = analyze_json(lines)
    elif log_format == "syslog":
        df = analyze_syslog(lines)
    elif log_format == "apache":
        df = analyze_apache(lines)
    else:
        df = analyze_generic(lines)

    if "timestamp" in df.columns:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        except:
            pass

    # === Sidebar Filters ===
    st.sidebar.header("🔍 Filters")
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

    if "level" in df.columns:
        levels = st.sidebar.multiselect("Log Levels", df["level"].unique(), default=[])
        if levels:
            df = df[df["level"].isin(levels)]

    if "module" in df.columns:
        modules = st.sidebar.multiselect("Modules", df["module"].unique(), default=[])
        if modules:
            df = df[df["module"].isin(modules)]

    if "ip" in df.columns and df["ip"].notna().any():
        ips = st.sidebar.multiselect("IP Addresses", df["ip"].dropna().unique(), default=[])
        if ips:
            df = df[df["ip"].isin(ips)]

    keyword = st.sidebar.text_input("Keyword Search")
    if keyword:
        df = df[df["message"].str.contains(keyword, case=False, na=False)]

    # === Display Data ===
    st.subheader("📋 Parsed Log Data")
    st.dataframe(df.head(50))

    if "level" in df.columns:
        st.subheader("📈 Log Level Distribution")
        st.bar_chart(df["level"].value_counts())

        if "timestamp" in df.columns and df["timestamp"].notna().any():
            st.subheader("📊 Log Level Timeline (stacked area)")
            timeline = df.groupby([pd.Grouper(key="timestamp", freq="1H"), "level"]).size().reset_index(name="count")
            chart = alt.Chart(timeline).mark_area().encode(
                x="timestamp:T",
                y="count:Q",
                color="level:N"
            )
            st.altair_chart(chart, use_container_width=True)

    if "timestamp" in df.columns and df["timestamp"].notna().any():
        st.subheader("⏳ Logs Over Time (Total)")
        ts_counts = df.set_index("timestamp").resample("1H").size()
        st.line_chart(ts_counts)

        st.subheader("📅 Activity Heatmap (Hour × Day)")
        heatmap_df = df.copy()
        heatmap_df["hour"] = heatmap_df["timestamp"].dt.hour
        heatmap_df["day"] = heatmap_df["timestamp"].dt.day_name()
        pivot = heatmap_df.pivot_table(index="day", columns="hour", values="message", aggfunc="count", fill_value=0)
        st.dataframe(pivot)

    if "module" in df.columns:
        st.subheader("📌 Error Density by Module")
        module_errs = df[df["level"].astype(str).str.upper() == "ERROR"]["module"].value_counts()
        st.bar_chart(module_errs)

    st.subheader("🔍 Error Clusters")
    clusters = cluster_errors(df)
    if clusters:
        cluster_df = pd.DataFrame(clusters, columns=["message", "cluster"])
        st.dataframe(cluster_df)
    else:
        st.info("No sufficient error messages to cluster.")

    st.subheader("🔥 Frequent Error Phrases (n-grams)")
    errors_only = df[df["level"].astype(str).str.upper() == "ERROR"]
    top_phrases = extract_top_error_phrases(errors_only["message"])
    if not isinstance(top_phrases, list) and not top_phrases.empty:
        st.dataframe(top_phrases)
    else:
        st.info("Not enough error messages for phrase extraction.")

    st.subheader("🔥 Frequent Messages")
    st.write(df["message"].value_counts().head(10))

    st.subheader("📥 Export Data")
    st.download_button("Download CSV", df.to_csv(index=False), "log_analysis.csv")
    st.download_button("Download JSON", df.to_json(orient='records', lines=True), "log_analysis.json")
