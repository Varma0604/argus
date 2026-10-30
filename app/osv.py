import httpx

from app.config import OSV_BATCH_API_URL
from app.scanner import Dependency


async def query_osv_batch(dependencies: list[Dependency], client: httpx.AsyncClient) -> list[list[dict]]:
    """Query OSV in batches while preserving order and skipping unpinned packages."""
    results: list[list[dict]] = [[] for _ in dependencies]
    indexed = [(index, dependency) for index, dependency in enumerate(dependencies) if dependency.version]
    for start in range(0, len(indexed), 1000):
        chunk = indexed[start:start + 1000]
        response = await client.post(OSV_BATCH_API_URL, json={"queries": [
            {"package": {"name": dependency.name, "ecosystem": dependency.ecosystem}, "version": dependency.version}
            for _, dependency in chunk
        ]})
        response.raise_for_status()
        items = response.json().get("results", [])
        if len(items) != len(chunk):
            raise ValueError("OSV returned a result count that did not match the batch request")
        for (index, _), item in zip(chunk, items):
            results[index] = item.get("vulns", [])
    return results
