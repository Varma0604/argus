# Argus

Argus scans dependency manifests in a public GitHub repository, parses Python and Node.js dependencies, and checks exact version pins against the [OSV vulnerability API](https://osv.dev/). It exposes scan submission and history through a FastAPI service and stores scan results in a configured SQL database. The Docker Compose deployment uses PostgreSQL and a Redis-backed scan worker; the local development default is SQLite with an in-process background task.

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

- Argus discovers `requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`, and `npm-shrinkwrap.json` anywhere in a repository's default branch. Private repositories and unsupported manifest formats are not supported.
- Only exact pins such as `urllib3==2.2.1` or `react@18.3.1` are looked up by version. Ranges and unpinned packages remain visible as unresolved dependencies.
- OSV requests are sent in batches of at most 1,000 exact dependencies. The response score is severity-weighted and capped at 100: critical 25, high 15, medium 8, low 3, and unknown 5 points per finding. It is a triage signal, not a security rating.
- Docker Compose uses Redis plus a separate worker. A worker records a lease while it scans; expired leases are returned to the queue. Local mode retains FastAPI's in-process task runner for learning without Redis.
- No throughput or latency benchmark is claimed yet. Record results with a repeatable workload before adding performance figures to a résumé.

## Design

`app/main.py` validates repository URLs, discovers supported manifests, creates scan records, and provides the HTTP API. `app/scanner.py` parses manifests. `app/osv.py` calls OSV's batch API. `app/queue.py` and `app/worker.py` implement the Redis-backed scan worker used by Docker Compose. SQLAlchemy models keep each scan and its findings as history.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

GitHub Actions runs the test suite on pushes and pull requests.

## Real-repository benchmark

After Docker Desktop is running, start the API, PostgreSQL, Redis, and worker:

```bash
docker compose up --build
python scripts/benchmark_real_repos.py https://github.com/psf/requests
```

The script records each repository URL, outcome, elapsed time, dependency count,
finding count, and risk score. Use only small public repositories that you are
comfortable requesting from GitHub and OSV; benchmark figures include external
network latency and should report the exact repository list and run date.
