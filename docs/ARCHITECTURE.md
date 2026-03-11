# Architecture — Log Analyzer Pro

This document explains how the codebase is structured, why it is structured that way,
and where to add things when extending the project.

---

## High-level overview

```
User uploads a log file
        │
        ▼
 ┌─────────────┐     detect_format()      ┌──────────────────┐
 │   app.py    │ ───────────────────────► │  src/utils/      │
 │  (Streamlit │                          │  io_utils.py     │
 │   entry     │ ◄─── format string ───── └──────────────────┘
 │   point)    │
 │             │     LogParser.parse()    ┌──────────────────┐
 │             │ ───────────────────────► │  src/parsers/    │
 │             │                          │  factory.py      │
 │             │ ◄─── pd.DataFrame ─────  └──────────────────┘
 │             │
 │             │     add_enrichments()   ┌──────────────────┐
 │             │ ───────────────────────► │  src/utils/      │
 │             │                          │  enrichment.py   │
 │             │ ◄─── enriched df ──────  └──────────────────┘
 │             │
 │             │     analytics fns       ┌──────────────────┐
 │             │ ───────────────────────► │  src/analytics/  │
 │             │ ◄─── results df ───────  └──────────────────┘
 │             │
 │             │     render tab          ┌──────────────────┐
 │             │ ───────────────────────► │  src/ui/tabs/    │
 └─────────────┘                          └──────────────────┘
```

Data flows in one direction only: **parse → enrich → analyse → render**.
No module calls back into `app.py` or into the UI layer.

---

## Directory structure

```
Log-analyser/
│
├── app.py                  Main Streamlit entry point
├── requirements.txt        Runtime dependencies
├── requirements-dev.txt    Development/test dependencies
├── setup.py                Package metadata and extras
├── pytest.ini              Test runner config
│
├── src/                    All importable source code
│   ├── __init__.py
│   │
│   ├── parsers/            Log format parsers
│   │   ├── __init__.py     Public re-exports
│   │   ├── base.py         BaseAnalyzer — shared JSON helpers
│   │   ├── factory.py      LogParser — format → parser dispatch
│   │   ├── standard.py     custom, syslog, apache, generic
│   │   ├── json_parsers.py json, docker_json, k8s, cloudwatch, gcp
│   │   └── xml_parsers.py  windows_event_xml
│   │
│   ├── analytics/          Analysis functions
│   │   ├── __init__.py     Public re-exports
│   │   ├── metrics.py      module_ranking, hourly_metrics, http_stats
│   │   └── ml_analytics.py cluster_errors, extract_top_error_phrases, sequence_mining
│   │
│   ├── utils/              Shared utilities
│   │   ├── __init__.py     Public re-exports
│   │   ├── patterns.py     CompiledPatterns (CP) — all pre-compiled regex
│   │   ├── enrichment.py   add_enrichments, redact_pii, detect_line_type, …
│   │   └── io_utils.py     iter_lines, merge_multiline_stack, detect_format
│   │
│   └── ui/                 Streamlit components
│       ├── __init__.py
│       └── tabs/
│           ├── __init__.py
│           ├── charts_tab.py
│           ├── heatmaps_tab.py
│           ├── types_tab.py
│           ├── clusters_tab.py
│           ├── anomalies_tab.py
│           └── sequences_tab.py
│
├── tests/
│   ├── conftest.py         Shared fixtures and sample log lines
│   ├── test_parsers.py
│   ├── test_analytics.py
│   └── test_utils.py
│
├── docs/
│   ├── ARCHITECTURE.md     ← this file
│   ├── API.md
│   ├── CHANGELOG.md
│   └── CONTRIBUTING.md
│
└── examples/
    ├── sample_apache.log
    ├── sample_syslog.log
    ├── sample_app.json
    ├── sample_custom.log
    └── analyse_programmatically.py
```

---

## Module responsibilities

### `src/parsers/`

**Single responsibility:** turn raw text lines into a normalised `pd.DataFrame`
with at minimum the columns `timestamp`, `level`, `module`, `message`.

| File | Contains |
|---|---|
| `base.py` | `BaseAnalyzer` — `safe_parse_json()`, `extract_common_json_fields()` |
| `factory.py` | `LogParser` — `parse(lines, format)`, `register_parser()`, `get_supported_formats()` |
| `standard.py` | `analyze_custom`, `analyze_syslog`, `analyze_apache`, `analyze_generic` |
| `json_parsers.py` | `analyze_json`, `analyze_docker_json`, `analyze_kubernetes_json`, `analyze_cloudwatch`, `analyze_gcp_cloud_logging` |
| `xml_parsers.py` | `analyze_windows_event_xml` |

**Design rule:** parsers must not import from `analytics/` or `ui/`.
They only import from `utils/patterns.py` and `base.py`.

**Adding a new parser:**
1. Create `src/parsers/my_format.py` with `analyze_my_format(lines: Iterator[str]) -> pd.DataFrame`
2. Add it to `PARSERS` dict in `factory.py`
3. Add a detection pattern to `CP.FORMAT_PATTERNS` in `utils/patterns.py`
4. Export it from `src/parsers/__init__.py`
5. Add tests in `tests/test_parsers.py`

---

### `src/utils/`

**Single responsibility:** shared tools used by parsers, analytics, and the app layer.

| File | Contains |
|---|---|
| `patterns.py` | `CompiledPatterns` (singleton `CP`) — every regex in the project, compiled once |
| `enrichment.py` | `add_enrichments()`, `detect_line_type()`, `parse_user_agent()`, `redact_pii()`, `parse_response_time()` |
| `io_utils.py` | `iter_lines()`, `merge_multiline_stack()`, `detect_format()` |

**Why a single `CompiledPatterns` class?**
Python compiles regex at the call site if you use `re.compile()` inside a function body.
Collecting all patterns into class attributes on `CP` means they are compiled exactly once
when the module is first imported, and reused for every log line thereafter.

**`lru_cache` strategy:**
- `detect_line_type` — 10 000 slot cache. Error messages repeat heavily in real logs.
- `parse_user_agent` — 5 000 slot cache. UA strings are typically site-wide constants.
- `detect_format` — unbounded `maxsize=1`. Called once per upload with the same 50-line sample.

---

### `src/analytics/`

**Single responsibility:** compute aggregations and ML results from an already-enriched
`pd.DataFrame`. Functions here are pure — they accept a DataFrame, return a DataFrame
or list, and have no side effects.

| File | Contains |
|---|---|
| `metrics.py` | `module_ranking()`, `hourly_metrics()`, `http_stats()` |
| `ml_analytics.py` | `cluster_errors()`, `extract_top_error_phrases()`, `sequence_mining()` |

**Anomaly detection approach:**
`hourly_metrics()` buckets logs into 1-hour windows, then computes a 24-hour rolling
mean and standard deviation for both total volume and error count. A z-score above 3
(±3σ) or an error ratio above 50% flags the hour as a spike. This is intentionally
simple — no ML dependency, runs in milliseconds on any size dataset.

---

### `src/ui/tabs/`

**Single responsibility:** render Streamlit UI for one analysis tab each.
Tab modules accept a filtered `pd.DataFrame` and produce no return value —
all output is via `st.*` calls.

Tab modules must not do any parsing, enrichment, or heavy computation themselves.
Heavy work belongs in `analytics/`. Tab functions call analytics functions, then
display results.

---

### `app.py`

The orchestrator. It:
1. Configures the Streamlit page
2. Renders the sidebar (settings + filters)
3. Calls `iter_lines` → `detect_format` → `LogParser.parse` → `add_enrichments`
4. Applies PII redaction if requested
5. Calls each tab renderer

`app.py` contains no business logic of its own — it only wires modules together.

---

## Data flow in detail

```
uploaded_file (Streamlit UploadedFile)
    │
    ▼ iter_lines()           — yields str lines, streaming, seek(0) first
    │
    ▼ detect_format()        — samples first 50 lines, returns format string
    │                          result is lru_cached so detection runs once
    │
    ▼ merge_multiline_stack() — (non-structured formats only)
    │                           collapses Java/Python stack traces into one entry
    │
    ▼ LogParser.parse()      — dispatches to the correct analyze_*() function
    │                          returns pd.DataFrame with normalised columns
    │
    ▼ pd.to_datetime()       — coerce timestamp column, errors='coerce'
    │
    ▼ add_enrichments()      — adds: line_type, request_type, request_path,
    │                          status_code, response_time_ms, user_id,
    │                          ua_browser, ua_os, ua_device, ip (fallback)
    │
    ▼ redact_pii()           — (optional, per user toggle)
    │                          replaces emails/IPs/UUIDs/tokens in message column
    │
    ▼ sidebar filters        — time range, level, module, keyword
    │                          produces filtered_df view (copy, not mutation)
    │
    ▼ tab renderers          — each tab receives filtered_df
                               calls analytics functions as needed
                               renders with st.* calls
```

---

## Design decisions and rationale

**Why Streamlit and not Flask/FastAPI + React?**
Streamlit lets data-focused developers ship a working interactive UI without
maintaining a separate frontend. The tradeoff is limited layout control and
no real-time push — acceptable for an upload-and-analyse workflow.

**Why KMeans for clustering?**
KMeans is fast, has no additional heavy dependencies beyond scikit-learn (which
is already required), and works well for grouping similar error messages by
TF-IDF similarity. The number of clusters is user-configurable. More advanced
approaches (HDBSCAN, sentence-transformers) are listed in the roadmap.

**Why regex-based parsing and not a log grammar library?**
Log formats are wildly inconsistent in the real world. Grammar-based parsers
(like `logparser`) tend to overfit specific format versions. Hand-crafted regex
with a fallback generic parser handles the 95% case reliably, and the factory
pattern makes it straightforward to add specialised parsers for edge cases.

**Why is `CompiledPatterns` a class and not a module-level dict?**
Class attributes are accessed by name (IDE autocomplete, `go to definition`),
whereas a plain dict requires string key lookups. The class has no `__init__`
or instance state — it is purely a namespace for compiled pattern objects.

---

## Adding a new analytics function

1. Add the function to the appropriate file in `src/analytics/`
2. Export it from `src/analytics/__init__.py`
3. Create a tab file in `src/ui/tabs/` that calls it and renders results
4. Import and call the tab renderer in `app.py`'s `render_analysis_tabs()`
5. Add tests in `tests/test_analytics.py`
