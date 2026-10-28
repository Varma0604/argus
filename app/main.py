import asyncio
import re
from contextlib import asynccontextmanager

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy.orm import Session

from app.config import GITHUB_RAW_BASE
from app.database import Base, engine, get_db
from app.models import DependencyRecord, Scan, Vulnerability
from app.osv import query_osv
from app.scanner import parse_requirements


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
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


async def run_scan(scan_id: int, repository_url: str, db: Session):
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = "running"
    db.commit()
    try:
        owner, repo = _repo_parts(repository_url)
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            metadata = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers={"Accept": "application/vnd.github+json"})
            if metadata.status_code == 404:
                raise ValueError("GitHub repository was not found or is not public")
            metadata.raise_for_status()
            branch = metadata.json().get("default_branch")
            if not branch or "/" in branch or branch in {".", ".."}:
                raise ValueError("Could not safely resolve the repository's default branch")
            raw_url = f"{GITHUB_RAW_BASE}/{owner}/{repo}/{branch}/requirements.txt"
            manifest = await client.get(raw_url)
            if manifest.status_code == 404:
                raise ValueError("Repository has no requirements.txt at its default branch root")
            manifest.raise_for_status()
            if len(manifest.content) > 2_000_000:
                raise ValueError("requirements.txt exceeds the 2 MB scan limit")
            dependencies = parse_requirements(manifest.text)
            semaphore = asyncio.Semaphore(10)

            async def lookup(dep):
                async with semaphore:
                    return await query_osv(dep, client)

            findings = await asyncio.gather(*(lookup(dep) for dep in dependencies))
            for dep, vulnerabilities in zip(dependencies, findings):
                record = DependencyRecord(scan_id=scan.id, name=dep.name, version=dep.version)
                db.add(record)
                db.flush()
                for vuln in vulnerabilities:
                    record.vulnerabilities.append(Vulnerability(
                        osv_id=vuln.get("id", "unknown"),
                        summary=vuln.get("summary") or vuln.get("details", "")[:500],
                        severity=(vuln.get("severity") or [{}])[0].get("score"),
                    ))
        db.flush()
        score = min(100, sum(25 for dep in scan.dependencies for _ in dep.vulnerabilities))
        scan.risk_score = score
        scan.status = "complete"
        db.commit()
    except Exception as exc:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:1000]
            db.commit()


def _background_scan(scan_id: int, url: str):
    from app.database import SessionLocal
    with SessionLocal() as db:
        asyncio.run(run_scan(scan_id, url, db))


@app.get("/health")
def health():
    return {"status": "ok", "service": "argus"}


@app.post("/api/v1/scans", status_code=202)
def create_scan(request: ScanRequest, background: BackgroundTasks, db: Session = Depends(get_db)):
    scan = Scan(repository_url=str(request.repository_url), status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background.add_task(_background_scan, scan.id, scan.repository_url)
    return {"scan_id": scan.id, "repository_url": scan.repository_url, "status": scan.status}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id, "repository_url": scan.repository_url, "status": scan.status,
        "risk_score": scan.risk_score, "error": scan.error,
        "dependencies": [{"name": d.name, "version": d.version,
            "vulnerabilities": [{"id": v.osv_id, "summary": v.summary, "severity": v.severity} for v in d.vulnerabilities]}
            for d in scan.dependencies],
    }


@app.get("/api/v1/scans")
def scan_history(db: Session = Depends(get_db)):
    return [{"scan_id": s.id, "repository_url": s.repository_url, "status": s.status,
             "risk_score": s.risk_score, "created_at": s.created_at}
            for s in db.query(Scan).order_by(Scan.created_at.desc()).limit(100)]
