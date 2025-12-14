# Contributing to Log Analyzer Pro

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Requests](#pull-requests)
- [Review Process](#review-process)

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We expect all contributors to:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing others' private information
- Other conduct inappropriate for a professional setting

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of log formats
- Familiarity with pandas and streamlit (helpful but not required)

### Finding Issues

1. Check [GitHub Issues](https://github.com/yourteam/Log-analyser/issues)
2. Look for labels:
   - `good first issue` - Great for newcomers
   - `help wanted` - We need help!
   - `bug` - Something isn't working
   - `enhancement` - New features
   - `documentation` - Documentation improvements

3. Comment on the issue to claim it

## 💻 Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/Log-analyser.git
cd Log-analyser
```

### 2. Create Virtual Environment

```bash
# Create venv
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### 4. Verify Setup

```bash
# Run tests
pytest

# Run linters
black --check src/
flake8 src/
mypy src/

# Start app
streamlit run app.py
```

## 🔧 Making Changes

### 1. Create a Branch

```bash
# Update main
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/my-awesome-feature

# Or for bug fixes
git checkout -b bugfix/fix-parser-issue
```

### Branch Naming Convention

- `feature/` - New features
- `bugfix/` - Bug fixes
- `docs/` - Documentation only
- `refactor/` - Code refactoring
- `test/` - Test additions/changes

### 2. Make Your Changes

#### Adding a New Parser

```python
# src/parsers/my_parser.py
import pandas as pd
from typing import Iterator

def analyze_my_format(lines: Iterator[str]) -> pd.DataFrame:
    """
    Parse my custom log format.
    
    Args:
        lines: Iterator of log lines
        
    Returns:
        pd.DataFrame: Parsed logs
    """
    data = []
    for line in lines:
        # Your parsing logic
        data.append({
            "timestamp": ...,
            "level": ...,
            "message": ...
        })
    return pd.DataFrame(data)
```

```python
# Register in src/parsers/factory.py
from .my_parser import analyze_my_format

class LogParser:
    PARSERS = {
        # ... existing parsers
        "my_format": analyze_my_format,
    }
```

#### Adding Tests

```python
# tests/test_my_parser.py
import pytest
from src.parsers.my_parser import analyze_my_format

def test_my_parser():
    """Test my custom parser."""
    sample_line = "2024-01-01 INFO: Test message"
    df = analyze_my_format(iter([sample_line]))
    
    assert len(df) == 1
    assert df.iloc[0]["level"] == "INFO"
```

### 3. Write Documentation

Update documentation for any user-facing changes:

- **README.md**: If adding major features
- **API.md**: If adding/changing APIs
- **Docstrings**: Always document functions

Example docstring:

```python
def my_function(param1: str, param2: int = 5) -> bool:
    """
    Brief description of what function does.
    
    More detailed explanation if needed. Can be multiple
    paragraphs.
    
    Args:
        param1: Description of param1
        param2: Description of param2 (default: 5)
        
    Returns:
        bool: Description of return value
        
    Raises:
        ValueError: When param1 is empty
        TypeError: When param2 is not an integer
        
    Example:
        >>> result = my_function("test", 10)
        >>> print(result)
        True
    """
    ...
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_parsers.py

# Run with coverage
pytest --cov=src --cov-report=html

# Run verbose
pytest -v
```

### Writing Tests

**Unit Tests**: Test individual functions

```python
def test_parse_timestamp():
    """Test timestamp parsing."""
    result = parse_timestamp("2024-01-01 12:00:00")
    assert result.year == 2024
    assert result.month == 1
```

**Integration Tests**: Test multiple components

```python
def test_full_pipeline():
    """Test complete parsing pipeline."""
    with open("fixtures/sample.log") as f:
        lines = iter_lines(f)
        df = LogParser.parse(lines, "apache")
        df = add_enrichments(df)
        assert not df.empty
        assert "line_type" in df.columns
```

### Test Coverage Requirements

- New code: 80%+ coverage
- Critical paths: 95%+ coverage
- Maintain overall: 85%+ coverage

## 🎨 Code Style

### Python Style Guide (PEP 8 + Black)

We use **Black** for automatic formatting:

```bash
# Format code
black src/

# Check formatting
black --check src/
```

### Key Style Points

1. **Line Length**: 88 characters (Black default)
2. **Imports**: Organized with isort
3. **Naming**:
   - `snake_case` for functions and variables
   - `PascalCase` for classes
   - `UPPER_CASE` for constants

4. **Type Hints**: Required for all public functions

```python
# Good
def parse_log(line: str) -> Dict[str, Any]:
    ...

# Bad
def parse_log(line):
    ...
```

### Linting

```bash
# Run all linters
flake8 src/
mypy src/
pylint src/

# Auto-fix imports
isort src/
```

## 📝 Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(parsers): add Kubernetes JSON parser

- Supports standard K8s JSON format
- Extracts namespace, pod, container metadata
- Includes comprehensive tests

Closes #123
```

```
fix(enrichment): correct timestamp parsing for syslog

The syslog parser was not handling years correctly.
Fixed by using the current year when not specified.

Fixes #456
```

### Best Practices

- Use present tense ("add" not "added")
- Be descriptive but concise
- Reference issues/PRs when applicable
- Explain *why*, not just *what*

## 🔄 Pull Requests

### Before Submitting

- [ ] Code passes all tests (`pytest`)
- [ ] Code passes linters (`black`, `flake8`, `mypy`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No merge conflicts with main

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Manual testing performed
- [ ] All tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings

## Screenshots (if applicable)
[Add screenshots for UI changes]

## Related Issues
Closes #123
```

### Submitting PR

```bash
# Push your branch
git push origin feature/my-feature

# Create PR on GitHub
# Fill out the PR template
# Request reviewers
```

## 👀 Review Process

### What Reviewers Look For

1. **Correctness**: Does it work as intended?
2. **Tests**: Adequate test coverage?
3. **Style**: Follows project conventions?
4. **Documentation**: Is it documented?
5. **Performance**: Any performance implications?
6. **Security**: Any security concerns?

### Addressing Feedback

```bash
# Make requested changes
git add .
git commit -m "refactor: address review feedback"

# Push changes
git push origin feature/my-feature

# PR automatically updates
```

### Approval Process

- **2 approvals** required
- All checks must pass
- No merge conflicts
- Squash and merge to main

## 🆘 Getting Help

### Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Email**: dev@yourteam.com
- **Documentation**: Check docs/ folder

### Tips for Getting Help

1. Search existing issues first
2. Provide minimal reproducible example
3. Include error messages and logs
4. Describe what you've tried
5. Be patient and respectful

## 🎯 Areas for Contribution

### High Priority

- Additional log format parsers
- Performance optimizations
- UI/UX improvements
- Documentation and examples

### Good First Issues

- Fix typos in documentation
- Add test cases
- Improve error messages
- Add code comments

### Advanced Contributions

- ML model improvements
- Real-time streaming support
- Plugin system
- API development

## 📚 Resources

### Learning Resources

- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [scikit-learn Documentation](https://scikit-learn.org/stable/)

### Project Resources

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Example Scripts](examples/)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Thank You!

Your contributions make this project better for everyone. We appreciate your time and effort!

---

**Questions?** Open an issue or reach out to the maintainers.

**Happy Contributing! 🎉**
