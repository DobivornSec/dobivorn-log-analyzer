# Dobivorn Log Analyzer v3.0

Dobivorn Log Analyzer is a modular CLI tool for analyzing Apache/Nginx access logs.
Version 3.0 introduces package-based architecture (`core`, `exporters`, `utils`) and test support.

## What's New in v3.0

- Modular codebase structure for maintainability
- Cleaner CLI entrypoint in `log_analyzer.py`
- Dedicated exporter modules (JSON, CSV, HTML)
- GeoIP utility class with caching
- Basic automated tests with `pytest`

## Project Structure

```text
.
├── core/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── constants.py
│   └── parser.py
├── exporters/
│   ├── __init__.py
│   ├── csv_exporter.py
│   ├── html_exporter.py
│   └── json_exporter.py
├── utils/
│   ├── __init__.py
│   └── geoip.py
├── tests/
│   └── test_analyzer.py
├── log_analyzer.py
├── sample.log
├── requirements.txt
└── requirements-dev.txt
```

## Installation

```bash
pip install -r requirements.txt
```

For test dependencies:

```bash
pip install -r requirements-dev.txt
```

## Usage

Basic analysis:

```bash
python log_analyzer.py sample.log
```

Export JSON/CSV/HTML:

```bash
python log_analyzer.py sample.log -j report.json -c report.csv --html report.html
```

Enable GeoIP:

```bash
python log_analyzer.py sample.log --geoip
```

Realtime mode:

```bash
python log_analyzer.py sample.log --realtime
```

## Run Tests

```bash
pytest -q
```

## Security Note

Use this tool only for authorized security monitoring and analysis.

