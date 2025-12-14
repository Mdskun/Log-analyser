import os
import re
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Iterator, List, Dict, Tuple, Optional
import streamlit as st
import altair as alt
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.cluster import KMeans

# COMPILED REGEX PATTERNS (for performance)
class CompiledPatterns:
    """Centralized compiled regex patterns for better performance"""
    # Format detection
    FORMAT_PATTERNS = {
        "custom": re.compile(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[\w+\] \[.*?\] .*"),
        "syslog": re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} .+"),
        "apache": re.compile(r"\d+\.\d+\.\d+\.\d+ - - \[.*?\] \".*?\" \d{3} \d+"),
        "json": re.compile(r"^\{.*\}$"),
        "docker_json": re.compile(r"^\{.*\"log\":.*\"time\":.*\}$"),
        "kubernetes_json": re.compile(r"^\{.*\"kubernetes\"\s*:\s*\{.*\}.*\}$"),
        "cloudwatch_export": re.compile(r"^\{.*\"logGroup\".*\"logStream\".*\"message\".*\}$"),
        "gcp_cloud_logging": re.compile(r"^\{.*(\"textPayload\"|\"jsonPayload\"|\"protoPayload\").*\}$"),
        "windows_event_xml": re.compile(r"^\s*<Event[ >].*")
    }
    
    # Multiline stack traces
    TS_START = re.compile(r"^(\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d+\.\d+\.\d+\.\d+ - - \[|<Event|\{)")
    CONTINUATION = re.compile(r"^(\s+|at\s|\.\.\.|Caused by:|Traceback|File \".+\", line \d+)")
    
    # Line type detection
    LINE_TYPES = [
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
    
    # Extraction patterns
    HTTP_PATH = re.compile(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\"]+)")
    HTTP_STATUS = re.compile(r"\s(\d{3})(?:\s|$)")
    HTTP_METHOD = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
    
    # PII patterns
    EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
    TOKEN = re.compile(r"\b(?:eyJ[\w-]+\.[\w-]+\.[\w-]+|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35})\b")
    USER_ID = re.compile(r"user[_-]?id\s*[:=]\s*([A-Za-z0-9_-]+)", re.I)
    RESPONSE_TIME = re.compile(r"(?:latency|response[_-]?time|request[_-]?time|duration|time)\s*[:=]\s*([0-9]*\.?[0-9]+)\s*(ms|s|sec|seconds)?", re.I)
    
    # User agent patterns
    UA_BROWSERS = [
        ("Chrome", re.compile(r"Chrome\/[0-9]+", re.I)),
        ("Firefox", re.compile(r"Firefox\/[0-9]+", re.I)),
        ("Safari", re.compile(r"Version\/[0-9].*Safari", re.I)),
        ("Edge", re.compile(r"Edg\/[0-9]+", re.I)),
        ("IE", re.compile(r"MSIE|Trident", re.I)),
    ]
    UA_OS = [
        ("Windows", re.compile(r"Windows NT", re.I)),
        ("macOS", re.compile(r"Mac OS X", re.I)),
        ("Linux", re.compile(r"Linux", re.I)),
        ("Android", re.compile(r"Android", re.I)),
        ("iOS", re.compile(r"iPhone|iPad", re.I)),
    ]
    UA_DEVICE = [
        ("Mobile", re.compile(r"Mobile|Android|iPhone|iPad", re.I)),
        ("Desktop", re.compile(r"Windows NT|Mac OS X|X11; Linux", re.I)),
    ]
    
    # Apache combined log format
    APACHE_COMBINED = re.compile(
        r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
        r"\"(?P<req>[A-Z]+ [^\s]+ [^\"]+)\" (?P<status>\d{3}) "
        r"(?P<size>\S+) \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\"")

CP = CompiledPatterns()

# FORMAT DETECTION & PREPROCESSING
@lru_cache(maxsize=1)
def detect_format(sample_tuple: Tuple[str, ...]) -> str:
    """Detect log format from sample lines. Cached for performance."""
    for fmt, pattern in CP.FORMAT_PATTERNS.items():
        for line in sample_tuple:
            if pattern.match(line.strip()):
                return fmt
    return "generic"

def merge_multiline_stack(iterable: Iterator[str]) -> Iterator[str]:
    """Efficiently merge stack trace continuation lines."""
    buf = []
    for raw in iterable:
        line = raw.rstrip("\n")
        if CP.TS_START.search(line):
            if buf:
                yield "\n".join(buf)
            buf = [line]
        elif CP.CONTINUATION.search(line):
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

# =============================
# BASE ANALYZER CLASS (eliminates duplication)
# =============================
class BaseAnalyzer:
    """Base class for log analyzers to reduce code duplication"""
    
    @staticmethod
    def safe_parse_json(line: str) -> Optional[Dict]:
        """Safely parse JSON line"""
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None
    
    @staticmethod
    def extract_common_json_fields(obj: Dict) -> Dict:
        """Extract common fields from JSON objects"""
        return {
            "timestamp": obj.get("timestamp") or obj.get("time") or obj.get("@timestamp"),
            "level": obj.get("level") or obj.get("severity") or obj.get("logLevel") or "UNKNOWN",
            "message": obj.get("message") or obj.get("msg") or obj.get("log") or obj.get("textPayload") or "",
            "ip": obj.get("ip") or obj.get("client_ip"),
            "user_agent": obj.get("user_agent") or obj.get("userAgent") or obj.get("httpUserAgent"),
            "status_code": obj.get("status") or obj.get("status_code"),
            "request_time": obj.get("response_time") or obj.get("latency") or obj.get("request_time"),
        }

# =============================
# SPECIALIZED ANALYZERS
# =============================
def analyze_custom(lines: Iterator[str]) -> pd.DataFrame:
    """Parse custom format logs"""
    pattern = re.compile(r"\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)")
    fmt = "%Y-%m-%d %H:%M:%S"
    data = []
    for line in lines:
        if m := pattern.match(line):
            try:
                data.append({
                    "timestamp": datetime.strptime(m.group(1), fmt),
                    "level": m.group(2),
                    "module": m.group(3),
                    "message": m.group(4)
                })
            except ValueError:
                continue
    return pd.DataFrame(data)

def analyze_json(lines: Iterator[str]) -> pd.DataFrame:
    """Parse generic JSON logs"""
    rows = []
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            row = BaseAnalyzer.extract_common_json_fields(obj)
            row["module"] = (obj.get("module") or obj.get("logger") or 
                           obj.get("logName") or obj.get("logStream") or "unknown")
            rows.append(row)
    return pd.DataFrame(rows)

def analyze_syslog(lines: Iterator[str]) -> pd.DataFrame:
    """Parse syslog format"""
    pattern = re.compile(r"^(\w{3} +\d+ \d{2}:\d{2}:\d{2}) (\S+) (.+?): (.*)")
    data = []
    for line in lines:
        if m := pattern.match(line):
            data.append({
                "timestamp": m.group(1),
                "level": "INFO",
                "module": m.group(3),
                "message": m.group(4),
                "ip": m.group(2)
            })
    return pd.DataFrame(data)

def analyze_apache(lines: Iterator[str]) -> pd.DataFrame:
    """Parse Apache combined log format"""
    data = []
    for line in lines:
        if m := CP.APACHE_COMBINED.match(line):
            d = m.groupdict()
            req_parts = d["req"].split(" ")
            data.append({
                "timestamp": d["ts"],
                "level": d["status"],
                "module": d["ip"],
                "message": d["req"],
                "ip": d["ip"],
                "status_code": d["status"],
                "user_agent": d["ua"],
                "request_type": req_parts[0] if req_parts else None,
                "request_path": req_parts[1] if len(req_parts) > 1 else None,
            })
    return pd.DataFrame(data)

def analyze_docker_json(lines: Iterator[str]) -> pd.DataFrame:
    """Parse Docker JSON file driver logs"""
    rows = []
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            rows.append({
                "timestamp": obj.get("time"),
                "level": obj.get("level", "INFO"),
                "module": obj.get("container_name") or obj.get("source", "docker"),
                "message": (obj.get("log") or "").rstrip(),
                "ip": None,
                "user_agent": obj.get("user_agent"),
            })
    return pd.DataFrame(rows)

def analyze_kubernetes_json(lines: Iterator[str]) -> pd.DataFrame:
    """Parse Kubernetes JSON logs"""
    rows = []
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            k8s = obj.get("kubernetes", {}) if isinstance(obj, dict) else {}
            module = "/".join(filter(None, [
                k8s.get("namespace_name"), 
                k8s.get("pod_name"), 
                k8s.get("container_name")
            ])) or "kubernetes"
            rows.append({
                "timestamp": obj.get("time") or obj.get("timestamp"),
                "level": obj.get("level") or obj.get("severity") or "INFO",
                "module": module,
                "message": obj.get("log") or obj.get("message") or "",
                "ip": None,
                "user_agent": obj.get("userAgent") or obj.get("httpUserAgent"),
            })
    return pd.DataFrame(rows)

def analyze_cloudwatch(lines: Iterator[str]) -> pd.DataFrame:
    """Parse AWS CloudWatch Logs export"""
    rows = []
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            rows.append({
                "timestamp": obj.get("timestamp"),
                "level": obj.get("level") or obj.get("severity") or "INFO",
                "module": obj.get("logGroup") or obj.get("logStream") or "cloudwatch",
                "message": obj.get("message") or obj.get("@message") or "",
                "ip": None,
                "user_agent": obj.get("userAgent")
            })
    return pd.DataFrame(rows)

def analyze_gcp_cloud_logging(lines: Iterator[str]) -> pd.DataFrame:
    """Parse GCP Cloud Logging export"""
    rows = []
    for line in lines:
        if obj := BaseAnalyzer.safe_parse_json(line):
            msg = obj.get("textPayload")
            if not msg and isinstance(obj.get("jsonPayload"), dict):
                msg = json.dumps(obj["jsonPayload"], ensure_ascii=False)
            if not msg and isinstance(obj.get("protoPayload"), dict):
                msg = json.dumps(obj["protoPayload"], ensure_ascii=False)
            
            http_req = obj.get("httpRequest", {})
            rows.append({
                "timestamp": obj.get("timestamp") or obj.get("receiveTimestamp"),
                "level": obj.get("severity", "INFO"),
                "module": (obj.get("logName") or "gcp").split("/")[-1],
                "message": msg or "",
                "ip": None,
                "user_agent": http_req.get("userAgent") if isinstance(http_req, dict) else None,
            })
    return pd.DataFrame(rows)

def analyze_windows_event_xml(lines: Iterator[str]) -> pd.DataFrame:
    """Parse Windows EventLog XML exports"""
    rows = []
    buf = []
    
    def flush_event(event_text: str):
        if not event_text:
            return
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
        elif buf:
            buf.append(line)
    return pd.DataFrame(rows)

def analyze_generic(lines: Iterator[str]) -> pd.DataFrame:
    """Parse generic/unknown format logs"""
    data = []
    ts_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2})")
    level_pattern = re.compile(r"\b(INFO|ERROR|WARN|WARNING|DEBUG|CRITICAL)\b", re.IGNORECASE)
    
    for line in lines:
        ts_match = ts_pattern.search(line)
        level_match = level_pattern.search(line)
        ip_match = CP.IPV4.search(line)
        
        data.append({
            "timestamp": ts_match.group(1) if ts_match else None,
            "level": level_match.group(1).upper() if level_match else "UNKNOWN",
            "module": "unknown",
            "message": line.strip(),
            "ip": ip_match.group(1) if ip_match else None
        })
    return pd.DataFrame(data)

# =============================
# ENRICHMENT FUNCTIONS
# =============================
@lru_cache(maxsize=10000)
def detect_line_type(msg: str) -> str:
    """Detect line type with caching for repeated messages"""
    if not isinstance(msg, str):
        return "UNKNOWN"
    for type_name, pattern in CP.LINE_TYPES:
        if pattern.search(msg):
            return type_name
    return "OTHER"

@lru_cache(maxsize=5000)
def parse_user_agent(ua: str) -> Tuple[str, str, str]:
    """Parse user agent with caching"""
    if not isinstance(ua, str) or not ua:
        return "Other", "Other", "Other"
    
    browser = next((name for name, rx in CP.UA_BROWSERS if rx.search(ua)), "Other")
    os_name = next((name for name, rx in CP.UA_OS if rx.search(ua)), "Other")
    device = next((name for name, rx in CP.UA_DEVICE if rx.search(ua)), "Other")
    return browser, os_name, device

def redact_pii(text: str) -> str:
    """Redact PII from text"""
    if not isinstance(text, str):
        return text
    text = CP.EMAIL.sub("<email>", text)
    text = CP.IPV4.sub("<ip>", text)
    text = CP.UUID.sub("<uuid>", text)
    text = CP.TOKEN.sub("<token>", text)
    return text

def parse_response_time(text: str) -> Optional[float]:
    """Extract response time in milliseconds"""
    if not isinstance(text, str):
        return None
    if m := CP.RESPONSE_TIME.search(text):
        try:
            val = float(m.group(1))
            unit = (m.group(2) or "ms").lower()
            return val * 1000.0 if unit in ["s", "sec", "seconds"] else val
        except ValueError:
            return None
    return None

def add_enrichments(df: pd.DataFrame) -> pd.DataFrame:
    """Add all enrichments to dataframe efficiently"""
    if df.empty:
        return df
    
    # Line types (vectorized where possible)
    if "message" in df.columns:
        df["line_type"] = df["message"].apply(detect_line_type)
    
    # Extract metadata from messages
    if "message" in df.columns:
        msg_series = df["message"].astype(str)
        df["request_type"] = msg_series.str.extract(CP.HTTP_METHOD, expand=False)
        df["request_path"] = msg_series.str.extract(CP.HTTP_PATH, expand=False)
        df["response_time_ms"] = msg_series.apply(parse_response_time)
        df["user_id"] = msg_series.str.extract(CP.USER_ID, expand=False)
        
        # Status code from level or message
        if "level" in df.columns:
            level_status = df["level"].astype(str).str.extract(r"^(\d{3})$", expand=False)
            msg_status = msg_series.str.extract(CP.HTTP_STATUS, expand=False)
            df["status_code"] = level_status.fillna(msg_status)
        
        # IP fallback from message if not present
        if "ip" not in df.columns or df["ip"].isna().all():
            df["ip"] = msg_series.str.extract(CP.IPV4, expand=False)
    
    # User agent parsing
    if "user_agent" in df.columns and df["user_agent"].notna().any():
        ua_parsed = df["user_agent"].apply(parse_user_agent)
        df["ua_browser"], df["ua_os"], df["ua_device"] = zip(*ua_parsed)
    
    return df

# =============================
# ANALYTICS FUNCTIONS
# =============================
def module_ranking(df: pd.DataFrame) -> pd.DataFrame:
    """Generate module ranking with error metrics"""
    if df.empty or "module" not in df.columns:
        return pd.DataFrame()
    
    # Efficient aggregation
    is_error = df["level"].astype(str).str.upper() == "ERROR"
    is_warn = df["level"].astype(str).str.upper().isin(["WARN", "WARNING"])
    
    result = df.groupby("module", dropna=False).agg(
        total=("message", "count"),
        errors=("message", lambda x: is_error[x.index].sum()),
        warns=("message", lambda x: is_warn[x.index].sum()),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max")
    ).reset_index()
    
    result["error_rate"] = (result["errors"] / result["total"]).round(3)
    
    # Add line type distribution
    if "line_type" in df.columns:
        types_pivot = df.pivot_table(
            index="module", columns="line_type", 
            values="message", aggfunc="count", fill_value=0
        )
        result = result.merge(types_pivot.reset_index(), on="module", how="left")
    
    return result.sort_values(["errors", "error_rate", "total"], ascending=[False, False, False])

def hourly_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate hourly metrics for anomaly detection"""
    if df.empty or "timestamp" not in df.columns or df["timestamp"].isna().all():
        return pd.DataFrame()
    
    tmp = df[df["timestamp"].notna()].copy()
    tmp["is_error"] = tmp["level"].astype(str).str.upper() == "ERROR"
    tmp = tmp.set_index("timestamp").sort_index()
    
    grp = tmp.resample("1H")
    res = pd.DataFrame({
        "count": grp.size(),
        "errors": grp["is_error"].sum(),
    })
    
    res["error_ratio"] = (res["errors"] / res["count"]).fillna(0.0)
    
    # Rolling statistics for anomaly detection
    window = 24
    res["count_ma"] = res["count"].rolling(window, min_periods=6).mean()
    res["count_std"] = res["count"].rolling(window, min_periods=6).std(ddof=0)
    res["z_count"] = (res["count"] - res["count_ma"]) / res["count_std"].replace(0, np.nan)
    
    res["errors_ma"] = res["errors"].rolling(window, min_periods=6).mean()
    res["errors_std"] = res["errors"].rolling(window, min_periods=6).std(ddof=0)
    res["z_errors"] = (res["errors"] - res["errors_ma"]) / res["errors_std"].replace(0, np.nan)
    
    res["spike"] = (res["z_count"].abs() > 3) | (res["z_errors"].abs() > 3) | (res["error_ratio"] > 0.5)
    
    return res.reset_index()

def cluster_errors(df: pd.DataFrame, n_clusters: int = 5) -> List[Tuple[str, int]]:
    """Cluster error messages using KMeans"""
    if df.empty or "level" not in df.columns:
        return []
    
    error_msgs = df[df["level"].astype(str).str.upper() == "ERROR"]["message"].fillna("")
    if len(error_msgs) < 2:
        return []
    
    try:
        vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
        X = vectorizer.fit_transform(error_msgs)
        
        n_clusters = min(n_clusters, len(error_msgs))
        model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        labels = model.fit_predict(X)
        
        return list(zip(error_msgs, labels))
    except Exception:
        return []

def extract_top_error_phrases(messages: pd.Series, top_n: int = 10) -> pd.DataFrame:
    """Extract common n-grams from error messages"""
    messages = [m for m in messages.fillna("") if m]
    if not messages:
        return pd.DataFrame(columns=["ngram", "count"])
    
    try:
        vectorizer = CountVectorizer(
            ngram_range=(2, 3), 
            stop_words="english", 
            max_features=2000
        )
        X = vectorizer.fit_transform(messages)
        freqs = X.sum(axis=0).A1
        terms = vectorizer.get_feature_names_out()
        
        freq_df = pd.DataFrame({"ngram": terms, "count": freqs})
        return freq_df.sort_values("count", ascending=False).head(top_n)
    except Exception:
        return pd.DataFrame(columns=["ngram", "count"])

def sequence_mining(df: pd.DataFrame, window_minutes: int = 5, 
                   seq_len: int = 3, top_k: int = 15) -> pd.DataFrame:
    """Mine common sequences before errors"""
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["sequence", "count"])
    
    work = df.sort_values("timestamp").copy()
    work["is_error"] = work["level"].astype(str).str.upper() == "ERROR"
    
    sequences = []
    error_rows = work[work["is_error"]]
    
    for idx, row in error_rows.iterrows():
        cutoff = row["timestamp"] - timedelta(minutes=window_minutes)
        window = work[(work["timestamp"] >= cutoff) & 
                     (work["timestamp"] < row["timestamp"])].tail(100)
        
        if window.empty:
            continue
        
        toks = (window["line_type"].fillna("NA") + ":" + 
               window["module"].astype(str).fillna("NA")).tolist()
        
        # Generate n-grams
        for L in range(2, seq_len + 1):
            for i in range(max(0, len(toks) - 50), len(toks) - L + 1):
                sequences.append(tuple(toks[i:i + L]))
    
    if not sequences:
        return pd.DataFrame(columns=["sequence", "count"])
    
    seq_series = pd.Series(sequences).value_counts().head(top_k)
    return seq_series.rename_axis("sequence").reset_index(name="count")

# =============================
# I/O UTILITIES
# =============================
def iter_lines(uploaded_file, encoding: str = "utf-8", errors: str = "ignore") -> Iterator[str]:
    """Memory-efficient line iteration"""
    uploaded_file.seek(0)
    for bline in uploaded_file:
        try:
            yield bline.decode(encoding, errors=errors).rstrip("\n")
        except Exception:
            continue

# STREAMLIT APP
def main():
    st.set_page_config(page_title="Log Analyzer Pro", layout="wide")
    st.title("📊 Advanced Log File Analyzer (Pro)")
    
    # Sidebar configuration
    st.sidebar.header("⚙️ Ingestion Settings")
    max_lines = st.sidebar.number_input(
        "Max lines to parse (0 = no cap)", 
        min_value=0, value=0, step=10000
    )
    
    uploaded_file = st.file_uploader(
        "Upload a log file", 
        type=["log", "txt", "json", "xml"]
    )
    
    if uploaded_file is None:
        st.info("👆 Upload a log file to begin analysis")
        return
    
    # Format detection
    with st.spinner("Analyzing log format..."):
        peek_lines = []
        for i, line in enumerate(iter_lines(uploaded_file)):
            peek_lines.append(line)
            if i >= 50:
                break
        
        log_format = detect_format(tuple(peek_lines))
        st.success(f"**Detected format:** {log_format}")
    
    # Select analyzer
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
    
    # Parse logs
    with st.spinner("Parsing log file..."):
        def limited_lines():
            for i, line in enumerate(iter_lines(uploaded_file)):
                if max_lines and i >= max_lines:
                    break
                yield line
        
        line_iter = limited_lines()
        
        # Apply multiline merging for non-structured formats
        structured_formats = {
            "json", "docker_json", "kubernetes_json", 
            "cloudwatch_export", "gcp_cloud_logging", "windows_event_xml"
        }
        if log_format not in structured_formats:
            line_iter = merge_multiline_stack(line_iter)
        
        df = analyzer(line_iter)
        
        if df.empty:
            st.error("No logs could be parsed from the file")
            return
    
    # Normalize timestamps
    with st.spinner("Processing timestamps..."):
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    
    # Apply enrichments
    with st.spinner("Enriching data..."):
        df = add_enrichments(df)
    
    # PII Redaction
    st.sidebar.header("🔐 Privacy")
    do_redact = st.sidebar.checkbox(
        "Redact PII (emails, IPs, UUIDs, tokens)", 
        value=False
    )
    display_col = "redacted_message" if do_redact else "message"
    if do_redact:
        df["redacted_message"] = df["message"].apply(redact_pii)
    
    # Create tabs
    tabs = st.tabs([
        "📋 Data", "📈 Charts", "🗺️ Heatmaps", 
        "🔎 Types & Ranking", "🤖 Clusters", 
        "🚨 Anomalies", "🧬 Sequences", "📥 Export"
    ])
    
    # Sidebar Filters
    st.sidebar.header("🔍 Filters")
    filtered_df = apply_filters(df, st.sidebar)
    
    # Tab 1: Data
    with tabs[0]:
        render_data_tab(filtered_df, display_col)
    
    # Tab 2: Charts
    with tabs[1]:
        render_charts_tab(filtered_df)
    
    # Tab 3: Heatmaps
    with tabs[2]:
        render_heatmaps_tab(filtered_df)
    
    # Tab 4: Types & Ranking
    with tabs[3]:
        render_types_ranking_tab(filtered_df)
    
    # Tab 5: Clusters
    with tabs[4]:
        render_clusters_tab(filtered_df)
    
    # Tab 6: Anomalies
    with tabs[5]:
        render_anomalies_tab(filtered_df)
    
    # Tab 7: Sequences
    with tabs[6]:
        render_sequences_tab(filtered_df)
    
    # Tab 8: Export
    with tabs[7]:
        render_export_tab(filtered_df, do_redact)

def apply_filters(df: pd.DataFrame, sidebar) -> pd.DataFrame:
    """Apply sidebar filters to dataframe"""
    filtered = df.copy()
    
    # Time range filter
    if "timestamp" in filtered.columns and filtered["timestamp"].notna().any():
        ts_clean = filtered["timestamp"].dropna()
        if not ts_clean.empty:
            min_time = ts_clean.min().to_pydatetime()
            max_time = ts_clean.max().to_pydatetime()
            
            time_range = sidebar.slider(
                "Time Range",
                min_value=min_time,
                max_value=max_time,
                value=(min_time, max_time)
            )
            filtered = filtered[
                (filtered["timestamp"] >= time_range[0]) & 
                (filtered["timestamp"] <= time_range[1])
            ]
    
    # Level filter
    if "level" in filtered.columns:
        all_levels = sorted(filtered["level"].unique().tolist())
        levels_sel = sidebar.multiselect("Log Levels", all_levels, default=[])
        if levels_sel:
            filtered = filtered[filtered["level"].isin(levels_sel)]
    
    # Module filter
    if "module" in filtered.columns:
        all_modules = sorted(filtered["module"].unique().tolist())
        modules_sel = sidebar.multiselect("Modules", all_modules, default=[])
        if modules_sel:
            filtered = filtered[filtered["module"].isin(modules_sel)]
    
    # IP filter
    if "ip" in filtered.columns and filtered["ip"].notna().any():
        all_ips = sorted(filtered["ip"].dropna().unique().tolist())
        ips_sel = sidebar.multiselect("IP Addresses", all_ips, default=[])
        if ips_sel:
            filtered = filtered[filtered["ip"].isin(ips_sel)]
    
    # Keyword filter
    keyword = sidebar.text_input("Keyword search")
    if keyword:
        filtered = filtered[
            filtered["message"].astype(str).str.contains(
                keyword, case=False, na=False
            )
        ]
    
    return filtered

def render_data_tab(df: pd.DataFrame, display_col: str):
    """Render data viewer tab with pagination"""
    st.subheader("Parsed Log Data")
    
    total_rows = len(df)
    page_size = st.number_input(
        "Rows per page", 
        min_value=50, max_value=5000, value=200, step=50
    )
    total_pages = max(1, (total_rows + page_size - 1) // page_size)
    page = st.number_input(
        "Page", 
        min_value=1, max_value=int(total_pages), value=1
    )
    
    start = (page - 1) * page_size
    end = min(page * page_size, total_rows)
    
    st.caption(f"Showing rows {start+1}-{end} of {total_rows}")
    
    # Optimize column order
    preferred_cols = [
        "timestamp", "level", "module", "ip", "status_code", 
        "request_type", "request_path", "response_time_ms", 
        "user_id", "ua_browser", "ua_os", "ua_device", display_col
    ]
    preferred_cols = [c for c in preferred_cols if c in df.columns]
    other_cols = [c for c in df.columns if c not in preferred_cols]
    
    st.dataframe(df[preferred_cols + other_cols].iloc[start:end])

def render_charts_tab(df: pd.DataFrame):
    """Render charts tab"""
    st.subheader("Log Analytics Charts")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if "level" in df.columns:
            st.write("**Log Level Distribution**")
            st.bar_chart(df["level"].value_counts())
    
    with col2:
        if "status_code" in df.columns and df["status_code"].notna().any():
            st.write("**HTTP Status Distribution**")
            st.bar_chart(df["status_code"].value_counts().sort_index())
    
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        st.subheader("Logs Over Time")
        ts_counts = df.set_index("timestamp").resample("1H").size().reset_index(name="count")
        st.line_chart(ts_counts.set_index("timestamp")["count"])
        
        if "level" in df.columns:
            st.subheader("Log Level Timeline")
            timeline = df.groupby([
                pd.Grouper(key="timestamp", freq="1H"), "level"
            ]).size().reset_index(name="count")
            
            chart = alt.Chart(timeline).mark_area().encode(
                x="timestamp:T",
                y="count:Q",
                color="level:N"
            )
            st.altair_chart(chart, use_container_width=True)
    
    if "response_time_ms" in df.columns and df["response_time_ms"].notna().any():
        st.subheader("Response Time Distribution")
        rt_df = df[["timestamp", "response_time_ms"]].dropna()
        st.line_chart(rt_df.set_index("timestamp")["response_time_ms"])

def render_heatmaps_tab(df: pd.DataFrame):
    """Render heatmaps tab"""
    st.subheader("Activity Heatmaps")
    
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        heatmap_df = df.copy()
        heatmap_df["hour"] = heatmap_df["timestamp"].dt.hour
        heatmap_df["day"] = heatmap_df["timestamp"].dt.day_name()
        
        pivot = heatmap_df.pivot_table(
            index="day", columns="hour", 
            values="message", aggfunc="count", fill_value=0
        )
        
        st.write("**Activity by Hour and Day**")
        st.dataframe(pivot)
    
    if "module" in df.columns:
        st.subheader("Error Density by Module")
        module_errs = df[
            df["level"].astype(str).str.upper() == "ERROR"
        ]["module"].value_counts()
        st.bar_chart(module_errs)

def render_types_ranking_tab(df: pd.DataFrame):
    """Render types and ranking tab"""
    st.subheader("Line Type Distribution")
    
    if "line_type" in df.columns:
        st.bar_chart(df["line_type"].value_counts())
    
    st.subheader("Module Ranking")
    rank_df = module_ranking(df)
    
    if not rank_df.empty:
        st.dataframe(rank_df)
        
        min_vol = st.number_input(
            "Min rows for error-rate chart", 
            min_value=1, value=20
        )
        top_rate = rank_df[rank_df["total"] >= min_vol].nlargest(10, "error_rate")
        
        if not top_rate.empty:
            st.bar_chart(top_rate.set_index("module")["error_rate"])
    else:
        st.info("No module statistics available")

def render_clusters_tab(df: pd.DataFrame):
    """Render clusters tab"""
    st.subheader("Error Clustering")
    
    n_clusters = st.slider("Number of clusters", 2, 10, 5)
    clusters = cluster_errors(df, n_clusters)
    
    if clusters:
        cluster_df = pd.DataFrame(clusters, columns=["message", "cluster"])
        st.dataframe(cluster_df)
        
        st.subheader("Frequent Error Phrases")
        errors_only = df[df["level"].astype(str).str.upper() == "ERROR"]
        top_phrases = extract_top_error_phrases(errors_only["message"])
        
        if not top_phrases.empty:
            st.dataframe(top_phrases)
        else:
            st.info("Not enough error messages for phrase extraction")
    else:
        st.info("No sufficient error messages to cluster")

def render_anomalies_tab(df: pd.DataFrame):
    """Render anomalies tab"""
    st.subheader("Anomaly Detection")
    
    metrics = hourly_metrics(df)
    
    if not metrics.empty:
        st.dataframe(metrics.tail(48))
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Error Ratio Over Time**")
            st.line_chart(metrics.set_index("timestamp")["error_ratio"])
        
        with col2:
            st.write("**Z-Score (Errors)**")
            st.line_chart(metrics.set_index("timestamp")["z_errors"].fillna(0))
        
        spikes = metrics[metrics["spike"]]
        if not spikes.empty:
            st.warning(f"⚠️ Detected {len(spikes)} spike hours")
            st.dataframe(spikes.tail(10))
    else:
        st.info("Need timestamps for anomaly detection")

def render_sequences_tab(df: pd.DataFrame):
    """Render sequences tab"""
    st.subheader("Sequence Mining")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        window = st.number_input("Window (minutes)", 1, 120, 5)
    with col2:
        seq_len = st.number_input("Max sequence length", 2, 6, 3)
    with col3:
        top_k = st.number_input("Top-K sequences", 5, 50, 15)
    
    seq_df = sequence_mining(
        df, window_minutes=window, 
        seq_len=int(seq_len), top_k=int(top_k)
    )
    
    if not seq_df.empty:
        st.dataframe(seq_df)
    else:
        st.info("No sequences found (need errors with prior context)")

def render_export_tab(df: pd.DataFrame, redact: bool):
    """Render export tab"""
    st.subheader("Export Data")
    
    export_df = df.copy()
    if redact:
        export_df["message"] = export_df["message"].apply(redact_pii)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.download_button(
            "📥 Download CSV",
            export_df.to_csv(index=False),
            "log_analysis.csv",
            mime="text/csv"
        )
    
    with col2:
        st.download_button(
            "📥 Download JSON",
            export_df.to_json(orient='records', lines=True),
            "log_analysis.json",
            mime="application/json"
        )
    
    st.caption(
        "Note: Binary .evtx files require additional packages. "
        "This tool supports XML exports."
    )

if __name__ == "__main__":
    main()