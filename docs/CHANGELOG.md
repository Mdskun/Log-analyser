# Changelog

All notable changes to Log Analyzer Pro are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [4.0.0] — 2024-12-01

This is the first full public release. The codebase was fully restructured from
a single-file monolith (`Analyser.py`) into a clean, modular package under `src/`.

### Added

**Core architecture**
- `src/parsers/` — dedicated parser module with a factory pattern (`LogParser`)
- `src/analytics/` — statistical metrics (`metrics.py`) and ML analytics (`ml_analytics.py`)
- `src/utils/` — shared patterns (`patterns.py`), enrichment (`enrichment.py`), I/O utilities (`io_utils.py`)
- `src/ui/tabs/` — full Streamlit tab implementations (Charts, Heatmaps, Types, Clusters, Anomalies, Sequences)

**Parsers**
- Custom structured format `[timestamp] [level] [module] message`
- Syslog (RFC 3164) with severity inference from message keywords
- Apache Combined Log Format
- Generic/unknown format with heuristic extraction
- Generic JSON logs
- Docker JSON file-driver logs
- Kubernetes JSON pod logs (namespace/pod/container metadata)
- AWS CloudWatch Logs export
- GCP Cloud Logging export (textPayload, jsonPayload, protoPayload)
- Windows Event Log XML exports

**Analytics**
- Module ranking by error rate and volume
- Hourly metrics with 24-hour rolling z-score anomaly detection
- KMeans error clustering (TF-IDF vectorisation)
- N-gram phrase extraction from error messages
- Sequence mining — finds recurring event patterns before errors
- HTTP statistics (top paths, status code distribution)

**Enrichment**
- Line type classification (HTTP_ACCESS, EXCEPTION, DB_ERROR, TIMEOUT, AUTH, NETWORK, RESOURCE, CONFIG, STARTUP_SHUTDOWN, GC)
- HTTP method and path extraction
- Response time extraction and normalisation (ms/s/sec → ms)
- User agent parsing (browser, OS, device)
- IP address extraction with valid-octet validation
- User ID extraction
- PII redaction (emails, IPs, UUIDs, JWT/AWS/GCP tokens)

**UI**
- 8-tab Streamlit interface: Data · Charts · Heatmaps · Types & Ranking · Clusters · Anomalies · Sequences · Export
- Sidebar filters: time range, log level, module, keyword search
- Paginated data viewer
- CSV and JSON export with optional PII redaction

**Performance**
- All regex patterns pre-compiled once at import time (`CompiledPatterns`)
- `lru_cache` on `detect_line_type` (10 000 slots) and `parse_user_agent` (5 000 slots)
- `detect_format` result cached — format detection runs once per upload
- Streaming line iteration — files are never fully loaded into memory

**Developer experience**
- Full test suite: `tests/test_parsers.py`, `tests/test_analytics.py`, `tests/test_utils.py` (~80 test cases)
- `pytest.ini` with `pythonpath = .` — tests run with `pytest` from the repo root, no install needed
- `setup.py` with `[dev]` and `[perf]` extras

### Fixed
- IPV4 regex now validates each octet is 0–255 (previously matched `999.999.999.999`)
- Syslog parser no longer hardcodes `level = "INFO"` — derives severity from message keywords
- Pandas resample alias updated from deprecated `"1H"` to `"h"` (pandas ≥ 2.2)

### Removed
- `Analyser.py` monolith (moved to `old_files/` for reference)

---

## [3.x] — Internal / Pre-release

Versions 1–3 were internal iterations building toward the modular architecture
released in v4.0.0. They are preserved in `old_files/` for historical reference
but are not supported.
