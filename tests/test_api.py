from fastapi.testclient import TestClient

from app.main import app


def test_health_and_repository_url_validation():
    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok", "service": "argus"}
        response = client.post("/api/v1/scans", json={"repository_url": "https://example.com/not/github"})
        assert response.status_code == 422
