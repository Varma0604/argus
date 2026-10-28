import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./argus.db")
OSV_API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/query")
GITHUB_RAW_BASE = os.getenv("GITHUB_RAW_BASE", "https://raw.githubusercontent.com")
