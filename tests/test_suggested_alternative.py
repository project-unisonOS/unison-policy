from fastapi.testclient import TestClient
from src.server import app

client = TestClient(app)


def test_require_confirmation_with_alternative():
    body = {
        "capability_id": "summarize.doc",
        "context": {"safety_context": {"data_classification": "confidential"}},
    }
    r = client.post("/evaluate", json=body)
    assert r.status_code == 200
    dec = r.json().get("decision", {})
    assert dec.get("allowed") is False
    assert dec.get("require_confirmation") is True
    assert isinstance(dec.get("suggested_alternative"), str) and len(dec.get("suggested_alternative")) > 0


def test_deny_with_alternative():
    body = {"capability_id": "delete.file", "context": {}}
    r = client.post("/evaluate", json=body)
    assert r.status_code == 200
    dec = r.json().get("decision", {})
    assert dec.get("allowed") is False
    assert dec.get("require_confirmation") is False
    assert isinstance(dec.get("suggested_alternative"), str) and len(dec.get("suggested_alternative")) > 0
