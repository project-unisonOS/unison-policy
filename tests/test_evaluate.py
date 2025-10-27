from fastapi.testclient import TestClient
from src.server import app


def test_health():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200


def test_evaluate_allows():
    client = TestClient(app)
    resp = client.post("/evaluate", json={"capability_id": "x.Y", "context": {"actor": "test"}})
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("decision", {}).get("allowed") is True
