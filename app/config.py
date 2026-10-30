import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./argus.db")
OSV_API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/query")
OSV_BATCH_API_URL = os.getenv("OSV_BATCH_API_URL", "https://api.osv.dev/v1/querybatch")
GITHUB_RAW_BASE = os.getenv("GITHUB_RAW_BASE", "https://raw.githubusercontent.com")
REDIS_URL = os.getenv("REDIS_URL")
SCAN_QUEUE_KEY = "argus:scans"
WORKER_LEASE_SECONDS = int(os.getenv("WORKER_LEASE_SECONDS", "120"))
