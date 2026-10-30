"""Redis-backed durable scan queue; local development falls back to BackgroundTasks."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import redis

from app.config import REDIS_URL, SCAN_QUEUE_KEY, WORKER_LEASE_SECONDS

client = redis.Redis.from_url(REDIS_URL, decode_responses=True) if REDIS_URL else None


def enqueue_scan(scan_id: int) -> bool:
    if client is None:
        return False
    client.zadd(SCAN_QUEUE_KEY, {str(scan_id): time.time()})
    return True


def pop_scan() -> int | None:
    if client is None:
        return None
    candidates = client.zrangebyscore(SCAN_QUEUE_KEY, "-inf", time.time(), start=0, num=1)
    if not candidates:
        return None
    scan_id = candidates[0]
    return int(scan_id) if client.zrem(SCAN_QUEUE_KEY, scan_id) else None


def recover_unfinished_scans(db) -> None:
    """Requeue scans lost between database commit, Redis enqueue, or a worker crash."""
    from app.models import Scan

    now = datetime.now(timezone.utc)
    rows = db.query(Scan).filter(
        (Scan.status == "queued") | ((Scan.status == "running") & (Scan.lease_expires_at <= now))
    ).all()
    for scan in rows:
        if scan.status == "running":
            scan.status = "queued"
            scan.lease_owner = None
            scan.lease_expires_at = None
            scan.error = "Worker lease expired; scan was requeued."
        enqueue_scan(scan.id)
    db.commit()
