# Argus

Argus scans dependency manifests in a public GitHub repository, parses Python and Node.js dependencies, and checks exact version pins against the [OSV vulnerability API](https://osv.dev/). It exposes scan submission and history through a FastAPI service and stores scan results in a configured SQL database. The Docker Compose deployment uses PostgreSQL and a Redis-backed scan worker; the local development default is SQLite with an in-process background task.

## Live demo

The public FastAPI documentation is available at
[argus-api-rr4l.onrender.com/docs](https://argus-api-rr4l.onrender.com/docs).
The deployment's health endpoint is
[`/health`](https://argus-api-rr4l.onrender.com/health). This is a portfolio
demo hosted on Render's free plan and may cold-start after inactivity.

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
- **Recorded benchmark (November 2, 2026):** three sequential end-to-end scans of
  [`axios/axios`](https://github.com/axios/axios) on an Apple Silicon Mac with
  Docker Desktop completed in 3.097--5.302 seconds (median **3.352 seconds**).
  Each completed scan recorded 1,036 resolved dependencies and 35 OSV findings.
  This is a single-repository, external-network measurement--not a general
  throughput claim--and the repository, run count, and date should accompany
  any résumé use of the figure.

## Design

`app/main.py` validates repository URLs, discovers supported manifests, creates scan records, and provides the HTTP API. `app/scanner.py` parses manifests. `app/osv.py` calls OSV's batch API. `app/queue.py` and `app/worker.py` implement the Redis-backed scan worker used by Docker Compose. SQLAlchemy models keep each scan and its findings as history.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

GitHub Actions runs the test suite on pushes and pull requests.

## Deploy a live demo on Render

`render.yaml` defines a public Docker web service and a managed PostgreSQL
database. Render injects the database connection string at deployment time;
Argus normalizes that URL for SQLAlchemy's `psycopg` driver. The hosted demo
uses FastAPI's in-process fallback for background scans when no Redis URL is
configured. The full Redis-worker architecture remains available through
`docker compose` for local development and systems testing.

To deploy, connect the GitHub repository in Render and create a new Blueprint
from the repository root. Choose the free plans only if you accept their
provider limits and expiration behavior. After deployment, verify
`https://<your-service>.onrender.com/health` and link the public URL only once
the endpoint responds successfully.

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
