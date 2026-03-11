"""
Log Analyzer Pro - Professional Log Analysis Tool
==================================================

A modular, high-performance log file analyzer with ML-powered insights.
"""

from setuptools import setup, find_packages
import os


def read_file(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, encoding="utf-8") as f:
            return f.read()
    return ""


INSTALL_REQUIRES = [
    "pandas>=2.0.0",
    "numpy>=1.24.0",
    "streamlit>=1.28.0",
    "altair>=5.0.0",
    "scikit-learn>=1.3.0",
    "pyarrow>=13.0.0",
]

EXTRAS_REQUIRE = {
    "dev": [
        "pytest>=7.4.0",
        "pytest-cov>=4.1.0",
        "black>=23.7.0",
        "flake8>=6.1.0",
        "mypy>=1.5.0",
        "pre-commit>=3.3.3",
    ],
    "perf": [
        "fastparquet>=2023.0.0",
    ],
}

setup(
    name="log-analyzer-pro",
    version="4.0.0",
    author="Your Team",
    author_email="dev@yourteam.com",
    description="Professional log analysis tool with ML-powered insights",
    long_description=read_file("README.md"),          # was README_NEW.md — file didn't exist
    long_description_content_type="text/markdown",
    url="https://github.com/yourteam/Log-analyser",
    project_urls={
        "Bug Tracker": "https://github.com/yourteam/Log-analyser/issues",
        "Documentation": "https://github.com/yourteam/Log-analyser/docs",
        "Source Code": "https://github.com/yourteam/Log-analyser",
    },
    packages=find_packages(include=["src", "src.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    # No console_scripts entry: the app is launched via `streamlit run app.py`
    # A plain entry_point cannot launch Streamlit correctly.
    include_package_data=True,
    zip_safe=False,
    keywords="log analyzer parser monitoring ml anomaly-detection",
)
