import httpx

from app.config import OSV_API_URL
from app.scanner import Dependency


async def query_osv(dependency: Dependency, client: httpx.AsyncClient) -> list[dict]:
    if dependency.version is None:
        return []
    response = await client.post(
        OSV_API_URL,
        json={"package": {"name": dependency.name, "ecosystem": "PyPI"}, "version": dependency.version},
    )
    response.raise_for_status()
    return response.json().get("vulns", [])
