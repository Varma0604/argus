import asyncio
import re
from contextlib import asynccontextmanager

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy.orm import Session

from app.config import GITHUB_RAW_BASE, WORKER_LEASE_SECONDS
from app.database import ensure_schema, get_db
from app.models import DependencyRecord, Scan, Vulnerability
from app.osv import query_osv_batch
from app.queue import enqueue_scan
from app.scanner import Dependency, parse_manifest


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Argus", description="Open source software supply-chain scanner", version="0.1.0", lifespan=lifespan)


class ScanRequest(BaseModel):
    repository_url: HttpUrl

    @field_validator("repository_url")
    @classmethod
    def public_github_repository(cls, value: HttpUrl):
        if value.host != "github.com" or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", value.path):
            raise ValueError("repository_url must be a public GitHub repository URL")
        return value


def _repo_parts(url: str) -> tuple[str, str]:
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?", url)
    if not match:
        raise ValueError("Invalid GitHub repository URL")
    return match.group(1), match.group(2).removesuffix(".git")


MANIFEST_NAMES = {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "npm-shrinkwrap.json"}


async def _get_with_retry(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    """Retry only transient GitHub/OSV-style failures with a bounded backoff."""
    response = None
    for attempt in range(3):
        response = await client.get(url, **kwargs)
        if response.status_code != 429 and response.status_code < 500:
            return response
        if attempt < 2:
            await asyncio.sleep(0.25 * (2 ** attempt))
    assert response is not None
    return response


def _severity_label(vulnerability: dict) -> str:
    label = vulnerability.get("database_specific", {}).get("severity")
    if isinstance(label, str) and label.upper() in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
        return "MEDIUM" if label.upper() == "MODERATE" else label.upper()
    return "UNKNOWN"


def _risk_points(severity: str) -> int:
    return {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "UNKNOWN": 5}[severity]


async def run_scan(scan_id: int, db: Session, worker_id: str | None = None):
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    repository_url = scan.repository_url
    scan.status = "running"
    if worker_id:
        from datetime import datetime, timedelta, timezone
        scan.lease_owner = worker_id
        scan.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=WORKER_LEASE_SECONDS)
    db.commit()
    try:
        owner, repo = _repo_parts(repository_url)
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            metadata = await _get_with_retry(client, f"https://api.github.com/repos/{owner}/{repo}", headers={"Accept": "application/vnd.github+json"})
            if metadata.status_code == 404:
                raise ValueError("GitHub repository was not found or is not public")
            metadata.raise_for_status()
            branch = metadata.json().get("default_branch")
            if not branch or "/" in branch or branch in {".", ".."}:
                raise ValueError("Could not safely resolve the repository's default branch")
            tree = await _get_with_retry(client, f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
                                         headers={"Accept": "application/vnd.github+json"})
            tree.raise_for_status()
            tree_data = tree.json()
            if tree_data.get("truncated"):
                raise ValueError("Repository tree is too large for safe manifest discovery")
            manifest_paths = sorted(item["path"] for item in tree_data.get("tree", [])
                                    if item.get("type") == "blob" and item.get("path", "").rsplit("/", 1)[-1] in MANIFEST_NAMES)
            if not manifest_paths:
                raise ValueError("Repository has no supported dependency manifest")
            if len(manifest_paths) > 100:
                raise ValueError("Repository has more than the 100 supported-manifest scan limit")
            dependencies: list[Dependency] = []
            for path in manifest_paths:
                manifest = await _get_with_retry(client, f"{GITHUB_RAW_BASE}/{owner}/{repo}/{branch}/{path}")
                manifest.raise_for_status()
                if len(manifest.content) > 2_000_000:
                    raise ValueError(f"{path} exceeds the 2 MB manifest limit")
                dependencies.extend(parse_manifest(path, manifest.text))
            findings = await query_osv_batch(dependencies, client)
            for dep, vulnerabilities in zip(dependencies, findings):
                record = DependencyRecord(scan_id=scan.id, name=dep.name, version=dep.version,
                                          ecosystem=dep.ecosystem, manifest_path=dep.manifest_path)
                db.add(record)
                db.flush()
                for vuln in vulnerabilities:
                    record.vulnerabilities.append(Vulnerability(
                        osv_id=vuln.get("id", "unknown"),
                        summary=vuln.get("summary") or vuln.get("details", "")[:500],
                        severity=_severity_label(vuln),
                    ))
        db.flush()
        score = min(100, sum(_risk_points(vulnerability.severity or "UNKNOWN")
                             for dependency in scan.dependencies for vulnerability in dependency.vulnerabilities))
        scan.risk_score = score
        scan.status = "complete"
        scan.lease_owner = None
        scan.lease_expires_at = None
        db.commit()
    except Exception as exc:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:1000]
            scan.lease_owner = None
            scan.lease_expires_at = None
            db.commit()


def _background_scan(scan_id: int):
    from app.database import SessionLocal
    with SessionLocal() as db:
        asyncio.run(run_scan(scan_id, db))


@app.get("/health")
def health():
    return {"status": "ok", "service": "argus"}


@app.post("/api/v1/scans", status_code=202)
def create_scan(request: ScanRequest, background: BackgroundTasks, db: Session = Depends(get_db)):
    scan = Scan(repository_url=str(request.repository_url), status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    if not enqueue_scan(scan.id):
        background.add_task(_background_scan, scan.id)
    return {"scan_id": scan.id, "repository_url": scan.repository_url, "status": scan.status}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id, "repository_url": scan.repository_url, "status": scan.status,
        "risk_score": scan.risk_score, "error": scan.error, "lease_owner": scan.lease_owner,
        "lease_expires_at": scan.lease_expires_at,
        "dependencies": [{"name": d.name, "version": d.version, "ecosystem": d.ecosystem, "manifest_path": d.manifest_path,
            "vulnerabilities": [{"id": v.osv_id, "summary": v.summary, "severity": v.severity} for v in d.vulnerabilities]}
            for d in scan.dependencies],
    }


@app.get("/api/v1/scans")
def scan_history(db: Session = Depends(get_db)):
    return [{"scan_id": s.id, "repository_url": s.repository_url, "status": s.status,
             "risk_score": s.risk_score, "created_at": s.created_at}
            for s in db.query(Scan).order_by(Scan.created_at.desc()).limit(100)]
