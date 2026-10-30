import httpx

from app.osv import query_osv_batch
from app.scanner import Dependency


async def test_batch_query_preserves_positions_and_skips_unpinned_dependencies():
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-1"}]}]})

    dependencies = [Dependency("requests", "2.31.0"), Dependency("fastapi", None)]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        results = await query_osv_batch(dependencies, client)

    assert results == [[{"id": "OSV-1"}], []]
    assert sent[0].url.path == "/v1/querybatch"
