# API Reference — Log Analyzer Pro

This document covers the public programmatic API. Everything here works
independently of Streamlit — you can use it in scripts, notebooks, or
other applications.

---

## Quick example

```python
from src.parsers import LogParser
from src.utils import iter_lines, detect_format, add_enrichments
from src.analytics import module_ranking, hourly_metrics

with open("app.log", "rb") as f:
    lines = list(iter_lines(f))

fmt = detect_format(tuple(lines[:50]))
df  = LogParser.parse(iter(lines), fmt)
df  = add_enrichments(df)

print(module_ranking(df).head())
print(hourly_metrics(df)[lambda x: x["spike"]].head())
```

---

## `src.utils.io_utils`

### `iter_lines(uploaded_file, encoding="utf-8", errors="ignore")`

Memory-efficient line iterator. Seeks to position 0 before iterating,
so it is safe to call multiple times on the same file object.

| Parameter | Type | Description |
|---|---|---|
| `uploaded_file` | file-like | Any object supporting `.seek()` and iteration (Streamlit `UploadedFile`, `open()` binary file, `io.BytesIO`) |
| `encoding` | `str` | Text encoding. Default `"utf-8"`. |
| `errors` | `str` | Encoding error strategy. Default `"ignore"`. |

**Yields:** `str` — one decoded line, trailing newline stripped.

---

### `detect_format(sample_tuple)`

Detect log format from a sample of lines. The result is `lru_cache`d —
calling it twice with the same tuple is free.

| Parameter | Type | Description |
|---|---|---|
| `sample_tuple` | `tuple[str, ...]` | A tuple of sample lines (use a tuple, not a list, for hashability) |

**Returns:** `str` — one of `"custom"`, `"syslog"`, `"apache"`, `"json"`,
`"docker_json"`, `"kubernetes_json"`, `"cloudwatch_export"`,
`"gcp_cloud_logging"`, `"windows_event_xml"`, `"generic"`.

```python
fmt = detect_format(tuple(lines[:50]))
# "apache"
```

---

### `merge_multiline_stack(iterable)`

Collapses multi-line stack traces into single entries. Identifies
continuation lines by leading whitespace, `at `, `Caused by:`,
`Traceback`, and similar markers.

| Parameter | Type | Description |
|---|---|---|
| `iterable` | `Iterator[str]` | Line iterator |

**Yields:** `str` — merged log entry (may contain embedded `\n` for stack frames).

---

## `src.parsers`

### `LogParser.parse(lines, format)`

Dispatch lines to the correct parser and return a normalised DataFrame.

| Parameter | Type | Description |
|---|---|---|
| `lines` | `Iterator[str]` | Line iterator |
| `format` | `str` | Format name from `detect_format()` |

**Returns:** `pd.DataFrame` with at minimum:

| Column | Type | Notes |
|---|---|---|
| `timestamp` | `str` or `datetime` | Raw string; call `pd.to_datetime(..., errors="coerce")` to convert |
| `level` | `str` | `INFO`, `ERROR`, `WARNING`, `DEBUG`, `CRITICAL`, `UNKNOWN` |
| `module` | `str` | Service / logger / container name |
| `message` | `str` | Full log message |
| `ip` | `str` or `None` | Source IP when available |

Additional columns vary by format (e.g. `status_code`, `user_agent`, `request_path`).

Falls back to `analyze_generic` for unknown format strings — never raises.

---

### `LogParser.register_parser(format_name, parser_func)`

Register a custom parser at runtime.

```python
import pandas as pd
from typing import Iterator
from src.parsers import LogParser

def analyze_my_format(lines: Iterator[str]) -> pd.DataFrame:
    data = []
    for line in lines:
        # your logic
        data.append({"timestamp": ..., "level": ..., "module": ..., "message": line})
    return pd.DataFrame(data)

LogParser.register_parser("my_format", analyze_my_format)

# Now usable:
df = LogParser.parse(iter(lines), "my_format")
```

---

### `LogParser.get_supported_formats()`

**Returns:** `list[str]` — names of all registered formats.

---

## `src.utils.enrichment`

### `add_enrichments(df)`

Apply all enrichments to an existing log DataFrame in-place. Safe to call
on an empty DataFrame (returns it unchanged).

| Parameter | Type | Description |
|---|---|---|
| `df` | `pd.DataFrame` | Output of any parser |

**Returns:** `pd.DataFrame` with additional columns:

| Column | Description |
|---|---|
| `line_type` | Classification: `HTTP_ACCESS`, `EXCEPTION`, `DB_ERROR`, `TIMEOUT`, `AUTH`, `NETWORK`, `RESOURCE`, `CONFIG`, `STARTUP_SHUTDOWN`, `GC`, `OTHER`, `UNKNOWN` |
| `request_type` | HTTP method (`GET`, `POST`, …) or `None` |
| `request_path` | URL path or `None` |
| `status_code` | HTTP status code or `None` |
| `response_time_ms` | Response time normalised to milliseconds, or `None` |
| `user_id` | Extracted `user_id=…` / `user-id=…` value, or `None` |
| `ua_browser` | Browser name from user-agent, or `"Other"` |
| `ua_os` | OS name from user-agent, or `"Other"` |
| `ua_device` | `"Mobile"`, `"Desktop"`, or `"Other"` |
| `ip` | IP address (falls back to extraction from message if not set by parser) |

---

### `redact_pii(text)`

Replace PII in a single string. Applies all redaction rules:
emails → `<email>`, IPs → `<ip>`, UUIDs → `<uuid>`, tokens → `<token>`.

| Parameter | Type | Description |
|---|---|---|
| `text` | `str` | Any string |

**Returns:** `str` with PII replaced, or the original value unchanged if not a string.

```python
from src.utils.enrichment import redact_pii

redact_pii("user@example.com logged in from 192.168.1.1")
# "<email> logged in from <ip>"
```

---

### `detect_line_type(msg)`

Classify a single log message. Cached — fast for repeated messages.

**Returns:** `str` — type name (see table above under `add_enrichments`).

---

### `parse_response_time(text)`

Extract response time and normalise to milliseconds.

```python
parse_response_time("latency=250ms")   # 250.0
parse_response_time("duration=1.5s")   # 1500.0
parse_response_time("no timing here")  # None
```

---

## `src.analytics`

### `module_ranking(df)`

Rank modules by error volume and error rate.

| Parameter | Type | Description |
|---|---|---|
| `df` | `pd.DataFrame` | Enriched log DataFrame |

**Returns:** `pd.DataFrame` sorted by `errors` descending, with columns:
`module`, `total`, `errors`, `warns`, `error_rate`, `first_seen`, `last_seen`,
plus one column per `line_type` if `line_type` is present in `df`.

---

### `hourly_metrics(df)`

Bucket logs into 1-hour windows and compute rolling anomaly statistics.

**Returns:** `pd.DataFrame` with columns:
`timestamp`, `count`, `errors`, `error_ratio`,
`count_ma`, `count_std`, `z_count`,
`errors_ma`, `errors_std`, `z_errors`, `spike`.

`spike` is `True` when `|z_count| > 3` **or** `|z_errors| > 3` **or** `error_ratio > 0.5`.

---

### `http_stats(df)`

**Returns:** `tuple[pd.Series, pd.Series]` — `(top_paths, status_distribution)`.

---

### `cluster_errors(df, n_clusters=5)`

KMeans cluster error messages using TF-IDF vectors.

**Returns:** `list[tuple[str, int]]` — `(message, cluster_label)` pairs,
or `[]` if fewer than 2 error messages exist.

---

### `extract_top_error_phrases(messages, top_n=10)`

Extract most-frequent 2–3 word n-grams from error messages.

| Parameter | Type | Description |
|---|---|---|
| `messages` | `pd.Series` | Series of message strings |
| `top_n` | `int` | Number of results to return |

**Returns:** `pd.DataFrame` with columns `ngram`, `count`, sorted descending.

---

### `sequence_mining(df, window_minutes=5, seq_len=3, top_k=15)`

Find recurring event-type sequences that precede error log entries.

| Parameter | Type | Description |
|---|---|---|
| `df` | `pd.DataFrame` | Enriched log DataFrame with `timestamp`, `level`, `line_type`, `module` |
| `window_minutes` | `int` | How far back before each error to look |
| `seq_len` | `int` | Maximum sequence length |
| `top_k` | `int` | Number of sequences to return |

**Returns:** `pd.DataFrame` with columns `sequence` (tuple) and `count`, sorted descending.

---

## `src.utils.patterns.CP`

A singleton instance of `CompiledPatterns` that holds every pre-compiled
regex pattern used by the project. Import it directly when you need a pattern:

```python
from src.utils.patterns import CP

if CP.IPV4.search(line):
    ip = CP.IPV4.search(line).group(0)

if CP.HTTP_METHOD.search(line):
    method = CP.HTTP_METHOD.search(line).group(1)
```

Key attributes: `FORMAT_PATTERNS`, `LINE_TYPES`, `HTTP_PATH`, `HTTP_STATUS`,
`HTTP_METHOD`, `APACHE_COMBINED`, `EMAIL`, `IPV4`, `UUID`, `TOKEN`,
`USER_ID`, `RESPONSE_TIME`, `UA_BROWSERS`, `UA_OS`, `UA_DEVICE`,
`TIMESTAMP`, `LOG_LEVEL`, `TS_START`, `CONTINUATION`.
