# Log Analyzer Pro 📊

> Professional log analysis tool with ML-powered insights and comprehensive format support

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Version](https://img.shields.io/badge/version-4.0.0-green.svg)](docs/CHANGELOG.md)

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/mdskun/Log-analyser.git
cd Log-analyser

# Install dependencies
pip install -r requirements.txt

# Run application
streamlit run app.py
```

Open your browser to `http://localhost:8501` and upload a log file.
Sample files are in the [`examples/`](examples/) folder if you want to try it immediately.

---

## ✨ Features

### 📁 Multiple Format Support
- **Standard Logs**: Syslog, Apache (Common/Combined), Custom `[timestamp][level][module]` format
- **JSON Logs**: Generic JSON, Docker, Kubernetes, AWS CloudWatch, GCP Cloud Logging
- **XML Logs**: Windows Event Logs (exported XML)
- **Auto-detection**: Smart format detection — just upload and go

### 📊 Powerful Analytics
- **Statistical Metrics**: Error rates, volume analysis, time-series aggregation
- **ML Clustering**: K-means clustering of error messages by semantic similarity
- **Anomaly Detection**: Statistical spike detection with 24-hour rolling z-scores
- **Sequence Mining**: Discover recurring event patterns that precede errors
- **Heatmaps**: Activity visualisation by time-of-day and module

### 🔐 Privacy & Security
- **PII Redaction**: Automatic removal of emails, IPs, UUIDs, JWT/AWS/GCP tokens
- **Configurable**: Toggle redaction on/off per session
- **Export Safe**: Redacted data flows through to CSV/JSON exports

### ⚡ Performance
- **Pre-compiled regex**: All patterns compiled once at import — zero per-line overhead
- **Streaming I/O**: Files are never fully loaded into memory — suitable for 100 MB+ files
- **LRU caching**: `detect_line_type` and `parse_user_agent` are cached across repeated values

---

## 📦 Installation

### Basic (run the app)

```bash
pip install -r requirements.txt
streamlit run app.py
```

### Developer (run tests + linters)

```bash
# Clone
git clone https://github.com/mdskun/Log-analyser.git
cd Log-analyser

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install with dev extras
pip install -e ".[dev]"

# Verify setup
pytest
streamlit run app.py
```

---

## 💻 Usage

### Web interface

1. Run `streamlit run app.py`
2. Upload any supported log file via the sidebar
3. Configure settings: max lines to parse, PII redaction toggle
4. Explore the eight analysis tabs:

| Tab | What it shows |
|---|---|
| 📋 Data | Paginated log viewer with column filters |
| 📈 Charts | Level distribution, HTTP status, time-series trends |
| 🗺️ Heatmaps | Activity by hour-of-day and day-of-week |
| 🔎 Types & Ranking | Module error ranking, line-type breakdown |
| 🤖 Clusters | K-means grouping of similar error messages |
| 🚨 Anomalies | Rolling z-score spike detection |
| 🧬 Sequences | Event patterns that precede errors |
| 📥 Export | Download filtered data as CSV or JSON |

### Programmatic usage

```python
from src.parsers import LogParser
from src.utils.io_utils import iter_lines, detect_format
from src.utils.enrichment import add_enrichments
from src.analytics.metrics import module_ranking, hourly_metrics

with open("app.log", "rb") as f:
    lines = list(iter_lines(f))

fmt = detect_format(tuple(lines[:50]))
df  = LogParser.parse(iter(lines), fmt)
df  = add_enrichments(df)

print(module_ranking(df).head())
print(hourly_metrics(df)[lambda x: x["spike"]].head())
```

See [`examples/analyse_programmatically.py`](examples/analyse_programmatically.py)
for a complete walkthrough covering all analytics functions.

### Registering a custom parser

```python
import pandas as pd
from typing import Iterator
from src.parsers import LogParser

def analyze_my_format(lines: Iterator[str]) -> pd.DataFrame:
    data = []
    for line in lines:
        data.append({"timestamp": ..., "level": ..., "module": ..., "message": line})
    return pd.DataFrame(data)

LogParser.register_parser("my_format", analyze_my_format)
df = LogParser.parse(iter(lines), "my_format")
```

---

## 🏗️ Architecture

```
Log-analyser/
├── app.py                  Streamlit entry point
├── src/
│   ├── parsers/            Log format parsers + factory
│   ├── analytics/          Statistical and ML analysis
│   ├── utils/              Regex patterns, enrichment, I/O
│   └── ui/tabs/            One file per Streamlit tab
├── tests/                  pytest test suite (~80 tests)
├── docs/                   Architecture, API, changelog, roadmap
└── examples/               Sample log files + usage script
```

Data flows in one direction: **parse → enrich → analyse → render**.
No module calls back into `app.py` or the UI layer.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design document,
including a flow diagram, module responsibilities, and guidance on extending the project.

---

## 🧪 Testing

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=src --cov-report=term-missing

# Single file
pytest tests/test_parsers.py -v
```

Tests cover parsers, analytics, enrichment, PII redaction, pattern correctness,
and the IPV4 octet-range validation. See [`tests/`](tests/) for details.

---

## 📈 Performance

| File Size | Lines | Parse Time | Peak Memory |
|---|---|---|---|
| 5 MB | ~50 000 | ~2 s | ~180 MB |
| 25 MB | ~250 000 | ~9 s | ~620 MB |
| 100 MB | ~1 000 000 | ~38 s | ~2.1 GB |

*Tested on: Intel Core i5-12400, 12 GB RAM, NVMe SSD, Python 3.11.*
Parse time includes format detection, enrichment, and all analytics.
For very large files, use the max-lines sidebar limit for initial exploration.

---

## 🗺️ Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full roadmap with status labels.

---

## 📝 Documentation

| Document | Description |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flow, module responsibilities |
| [API.md](docs/API.md) | Full programmatic API reference |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history |
| [ROADMAP.md](docs/ROADMAP.md) | Planned features |

---

## 🐛 Issues & Support

- **Bug Reports**: [GitHub Issues](https://github.com/mdskun/Log-analyser/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/mdskun/Log-analyser/discussions)
- **Contact**: manthandsoni@gmail.com

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with [Streamlit](https://streamlit.io/) · [Pandas](https://pandas.pydata.org/) · [scikit-learn](https://scikit-learn.org/) · [Altair](https://altair-viz.github.io/)

---

**Made by [Manthan D Soni](https://github.com/mdskun)** · [⭐ Star on GitHub](https://github.com/mdskun/Log-analyser)
