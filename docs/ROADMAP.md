# Roadmap — Log Analyzer Pro

This document describes what is planned, what is being actively considered,
and what is intentionally out of scope. It is updated with each release.

Status labels: ✅ Done · 🔄 In progress · 📋 Planned · 💡 Under consideration · ❌ Out of scope

---

## v4.0.0 — Initial release

| Feature | Status |
|---|---|
| Modular parser architecture (custom, syslog, apache, JSON, XML) | ✅ |
| KMeans error clustering with TF-IDF | ✅ |
| Anomaly detection with rolling z-scores | ✅ |
| Sequence mining (event patterns before errors) | ✅ |
| PII redaction (emails, IPs, UUIDs, tokens) | ✅ |
| 8-tab Streamlit UI | ✅ |
| CSV and JSON export | ✅ |
| Full test suite | ✅ |

---
## [4.0.1] — 2025-05-10

Expanded deployment options and format support.

| Feature | Status |
|---|---|
| Docker support (Dockerfile + docker-compose.yml) | ✅ |
| Apache mod_jk log type parser | ✅ |
---
## v4.1 — Next release

Focus: **usability and performance for larger files.**

| Feature | Status | Notes |
|---|---|---|
| ML algorithum Customization | 📋 | Let users set their own z-score and error-ratio thresholds from the sidebar |
| Real benchmark numbers in README | 📋 | Run against 10 MB / 50 MB / 100 MB files and publish actual timings |
| Support gzip-compressed log files | 📋 | Auto-detect `.gz` on upload |

---

## v4.2 — Future release

Focus: **multi-file analysis and richer ML insights.**

| Feature | Status | Notes |
|---|---|---|
| Better clustering model | 💡 | HDBSCAN or sentence-transformers for semantic grouping |
| Log sampling for very large files | 💡 | Reservoir sampling so 1 GB files are still analysable |
| DuckDB backend | 💡 | Replace in-memory pandas for files that exceed available RAM |

---

## Long-term

Focus: **advanced analysis features and ecosystem expansion.**

| Feature | Status | Notes |
|---|---|---|
| Time-range comparison view (insight dashboard) | 💡 | Compare "last hour" vs "same hour yesterday" or historical patterns |
| Log stories/automated reporting | 💡 | Convert logs to narrative stories or executive reports |
| CI/CD integration | 💡 | GitHub Actions workflow for automated testing and releases |
| Plugin system | 💡 | Third-party parsers and analytics as installable packages |

---

## Intentionally out of scope

| Feature | Reason |
|---|---|
| Persistent storage or a database backend | Keeping the tool stateless means zero infrastructure to manage |
| User accounts / multi-tenancy | Single-user local/intranet tool by design |
| Cloud-hosted SaaS version | No plans — the tool is designed to run locally where your logs are |

---

## Contributing to the roadmap

Have a feature request? Open a [GitHub Discussion](https://github.com/manthandsoni/Log-analyser/discussions)
with the label `feature-request`. Ideas that get community interest are moved into
the roadmap. Bug reports go in [Issues](https://github.com/manthandsoni/Log-analyser/issues).
