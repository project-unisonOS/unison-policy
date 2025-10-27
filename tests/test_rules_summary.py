from fastapi.testclient import TestClient
from src.server import app


def test_rules_summary_endpoint():
    client = TestClient(app)
    resp = client.get("/rules/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body.get("count"), int)
    assert "path" in body
