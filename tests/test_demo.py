from fastapi.testclient import TestClient

from aiof.web.app import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "allinoneforensics", "demo": False}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_demo_is_synthetic_and_read_only() -> None:
    response = client.get("/api/v1/demo")
    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "synthetic-read-only"
    assert payload["notice"] == "All data is synthetic."
    assert payload["case_id"] == "DEMO-2026-001"
    assert len(payload["evidence"]) == 2


def test_demo_page_contains_guided_workflow_and_audio() -> None:
    response = client.get("/demo")
    assert response.status_code == 200
    assert "How an investigation works" in response.text
    assert "Synthetic data only" in response.text
    assert "Read the tutorial" in response.text
    assert "speechSynthesis" in response.text


def test_demo_does_not_expose_local_cases() -> None:
    response = client.get("/demo")
    assert ".aiof" not in response.text
    assert "127.0.0.1 Secure" not in response.text
