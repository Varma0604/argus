import os

def _database_url() -> str:
    """Normalize managed-Postgres URLs for SQLAlchemy's installed psycopg driver."""
    value = os.getenv("DATABASE_URL", "sqlite:///./argus.db")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    return value


DATABASE_URL = _database_url()
OSV_API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/query")
OSV_BATCH_API_URL = os.getenv("OSV_BATCH_API_URL", "https://api.osv.dev/v1/querybatch")
GITHUB_RAW_BASE = os.getenv("GITHUB_RAW_BASE", "https://raw.githubusercontent.com")
REDIS_URL = os.getenv("REDIS_URL")
SCAN_QUEUE_KEY = "argus:scans"
WORKER_LEASE_SECONDS = int(os.getenv("WORKER_LEASE_SECONDS", "120"))
