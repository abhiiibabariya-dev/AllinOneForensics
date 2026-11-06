from fastapi.testclient import TestClient

from aiof.web.app import app


client = TestClient(app)


def test_cors_is_restricted_by_default() -> None:
    response = client.get("/healthz", headers={"Origin": "https://untrusted.example"})
    assert "access-control-allow-origin" not in response.headers


def test_protected_route_requires_auth_when_enabled(monkeypatch) -> None:
    from aiof.core.config import DEFAULT_CONFIG

    monkeypatch.setattr(DEFAULT_CONFIG, "require_auth", True)
    monkeypatch.setattr(DEFAULT_CONFIG, "api_token", "test-token")
    try:
        response = client.get("/")
        assert response.status_code == 401
        response = client.get("/", headers={"Authorization": "Bearer test-token"})
        assert response.status_code == 200
    finally:
        monkeypatch.setattr(DEFAULT_CONFIG, "require_auth", False)
        monkeypatch.setattr(DEFAULT_CONFIG, "api_token", "")


def test_oversized_request_is_rejected() -> None:
    response = client.post(
        "/api/v1/alerts/ingest",
        content="{}",
        headers={"Content-Length": "1048577", "Content-Type": "application/json"},
    )
    assert response.status_code == 413
