"""Durable Argus scan worker for Redis/PostgreSQL deployments."""

import asyncio
import os
import socket
import time

from app.database import SessionLocal, ensure_schema
from app.main import run_scan
from app.queue import pop_scan, recover_unfinished_scans

WORKER_ID = os.getenv("WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")


def main():
    ensure_schema()
    while True:
        with SessionLocal() as db:
            recover_unfinished_scans(db)
        scan_id = pop_scan()
        if scan_id is None:
            time.sleep(1)
            continue
        with SessionLocal() as db:
            asyncio.run(run_scan(scan_id, db, worker_id=WORKER_ID))


if __name__ == "__main__":
    main()
