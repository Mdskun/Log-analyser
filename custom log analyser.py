import os
import re
import json
import csv
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# === Auto-log File Finder ===
def find_log_file():
    log_candidates = [f for f in os.listdir('.') if f.endswith(('.log', '.txt')) and os.path.isfile(f)]
    if not log_candidates:
        print("No log files found in current directory.")
        exit(1)
    latest_log = max(log_candidates, key=os.path.getmtime)
    print(f"Auto-detected log file: {latest_log}")
    return latest_log

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
    return None

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
                "message": obj.get("message", "")
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
            try:
                dt = datetime.strptime(ts, "%b %d %H:%M:%S")
            except:
                dt = None
            data.append({"timestamp": ts, "level": "INFO", "module": module, "message": msg})
    return pd.DataFrame(data)

def analyze_apache(lines):
    data = []
    for line in lines:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?\"(.*?)\" (\d{3})", line)
        if m:
            ip, ts, req, code = m.groups()
            data.append({"timestamp": ts, "level": code, "module": ip, "message": req})
    return pd.DataFrame(data)

# === Clustering Errors ===
def cluster_errors(df, n_clusters=5):
    error_msgs = df[df["level"].str.upper() == "ERROR"]["message"]
    if len(error_msgs) < 2:
        return []
    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(error_msgs)
    model = KMeans(n_clusters=min(n_clusters, len(error_msgs)), random_state=42)
    labels = model.fit_predict(X)
    clustered = list(zip(error_msgs, labels))
    return clustered

# === Charting ===
def generate_charts(df, report_dir):
    plt.figure(figsize=(8, 4))
    df['level'].value_counts().plot(kind='bar', color='skyblue')
    plt.title("Log Levels")
    plt.xlabel("Level")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(report_dir, "log_levels.png"))
    plt.close()

    if 'module' in df.columns:
        top_mods = df['module'].value_counts().head(5)
        top_mods.plot(kind='pie', autopct='%1.1f%%', startangle=90)
        plt.title("Top Modules")
        plt.ylabel("")
        plt.tight_layout()
        plt.savefig(os.path.join(report_dir, "top_modules.png"))
        plt.close()

# === Exporting ===
def export(df, clusters, report_dir):
    df.to_csv(os.path.join(report_dir, "log_analysis.csv"), index=False)
    df.to_json(os.path.join(report_dir, "log_analysis.json"), orient='records', lines=True)

    if clusters:
        with open(os.path.join(report_dir, "error_clusters.csv"), "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["message", "cluster"])
            for msg, cl in clusters:
                writer.writerow([msg, cl])

# === Main ===
def analyze_log(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    log_format = detect_format(lines[:10])
    print(f"Detected format: {log_format}")

    if log_format == "custom":
        df = analyze_custom(lines)
    elif log_format == "json":
        df = analyze_json(lines)
    elif log_format == "syslog":
        df = analyze_syslog(lines)
    elif log_format == "apache":
        df = analyze_apache(lines)
    else:
        print("Unsupported or unknown format.")
        return

    ts_dir = datetime.now().strftime("log_report_%Y%m%d_%H%M%S")
    os.makedirs(ts_dir, exist_ok=True)

    # Generate visual reports
    generate_charts(df, ts_dir)

    # Cluster similar errors
    clusters = cluster_errors(df)

    # Save everything
    export(df, clusters, ts_dir)

    print(f"✅ Report saved to ./{ts_dir}")

# === Run ===
if __name__ == "__main__":
    log_file = find_log_file()
    analyze_log(log_file)
