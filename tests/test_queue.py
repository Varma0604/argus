from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models import Scan
from app.queue import recover_unfinished_scans


def test_expired_scan_lease_returns_scan_to_queued_state():
    with SessionLocal() as db:
        db.add(Scan(
            repository_url="https://github.com/example/repository",
            status="running",
            lease_owner="worker-that-crashed",
            lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        ))
        db.commit()
        scan_id = db.query(Scan).one().id

    with SessionLocal() as db:
        recover_unfinished_scans(db)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "queued"
        assert scan.lease_owner is None
        assert scan.lease_expires_at is None
        assert "lease expired" in scan.error.lower()
