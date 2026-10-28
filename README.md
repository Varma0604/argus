# Argus

Argus scans a public GitHub repository's root `requirements.txt`, parses Python dependencies, and checks exact version pins against the [OSV vulnerability API](https://osv.dev/). It exposes scan submission and history through a FastAPI service and stores scan results in PostgreSQL.

## Run locally

```bash
docker compose up --build
```

Open `http://localhost:8000/docs`. Submit a scan:

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"repository_url":"https://github.com/psf/requests"}'
```

The response includes a `scan_id`; poll `GET /api/v1/scans/{scan_id}` until the status is `complete` or `failed`. `GET /api/v1/scans` lists recent scan history. Health is at `GET /health`.

## Current behavior and limits

- The first version reads only a root-level `requirements.txt` from the repository's default branch. Private repositories and other manifest formats are not supported.
- Only exact pins such as `urllib3==2.2.1` are looked up by version. Ranges and unpinned packages remain visible as unresolved dependencies.
- The response risk score is intentionally simple: 25 points per known vulnerability, capped at 100. It is not a severity-calibrated security rating.
- Background scans use FastAPI's in-process task runner. A process restart can interrupt an active scan; saved scan history remains available.
- No throughput or latency benchmark is claimed yet. Record results with a repeatable workload before adding performance figures to a résumé.

## Design

`app/main.py` validates repository URLs, creates scan records, and provides the HTTP API. `app/scanner.py` parses the manifest. `app/osv.py` calls OSV. SQLAlchemy models keep each scan and its findings as history. Manifest URLs are built from validated GitHub repository paths.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

GitHub Actions runs the test suite on pushes and pull requests.
