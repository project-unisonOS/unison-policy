from fastapi.testclient import TestClient
from src.server import app, _RULES, _time_in_window, _matches_persons
import json
from datetime import datetime, timezone

client = TestClient(app)


def test_time_in_window():
    # Simple same-day ranges
    assert _time_in_window("09:00", "17:00")  # depends on current UTC time; we will mock in tests if needed
    # Cross-midnight
    assert _time_in_window("22:00", "02:00")  # also depends on current time

def test_matches_persons():
    assert _matches_persons(["alice", "bob"], "alice") is True
    assert _matches_persons(["alice", "bob"], "charlie") is False
    assert _matches_persons([], "alice") is False
    assert _matches_persons(None, "alice") is False

def test_rules_list():
    r = client.get("/rules")
    assert r.status_code == 200
    j = r.json()
    assert j.get("ok") is True
    assert isinstance(j.get("rules"), list)
    assert isinstance(j.get("count"), int)

def test_update_rules_invalid_payload():
    r = client.post("/rules", json={})
    assert r.status_code == 400
    j = r.json()
    assert "rules" in str(j.get("detail", "")).lower()

def test_update_rules_malformed_rule():
    r = client.post("/rules", json={"rules": [{"match": {}}]})
    assert r.status_code == 400
    j = r.json()
    assert "decision" in str(j.get("detail", "")).lower()

def test_update_rules_success():
    new_rules = [
        {
            "match": {"intent_prefix": "test.", "auth_scope": "person.local.explicit"},
            "decision": {"action": "allow", "reason": "test-allow"}
        }
    ]
    r = client.post("/rules", json={"rules": new_rules})
    assert r.status_code == 200
    j = r.json()
    assert j.get("ok") is True
    # Verify list reflects new rules
    r2 = client.get("/rules")
    assert r2.status_code == 200
    j2 = r2.json()
    assert any(rule.get("match", {}).get("intent_prefix") == "test." for rule in j2.get("rules", []))

def test_evaluate_auth_scope():
    payload = {
        "capability_id": "admin.delete",
        "context": {"auth_scope": "person.local.explicit"}
    }
    r = client.post("/evaluate", json=payload)
    assert r.status_code == 200
    j = r.json()
    decision = j.get("decision", {})
    # Default rules should deny admin actions for person.local.explicit
    assert decision.get("allowed") is False
    assert decision.get("reason") == "admin-actions-require-org-policy"

def test_evaluate_time_window_allowed():
    payload = {
        "capability_id": "sensitive.read",
        "context": {}
    }
    r = client.post("/evaluate", json=payload)
    assert r.status_code == 200
    j = r.json()
    decision = j.get("decision", {})
    # If current UTC time is within 09:00-17:00, should allow; else require confirmation
    assert decision.get("reason") in {"sensitive-allowed-during-business-hours", "sensitive-outside-hours-confirmation"}

def test_evaluate_per_person_allowed():
    payload = {
        "capability_id": "beta.try",
        "context": {"person_id": "alice"}
    }
    r = client.post("/evaluate", json=payload)
    assert r.status_code == 200
    j = r.json()
    decision = j.get("decision", {})
    assert decision.get("allowed") is True
    assert decision.get("reason") == "beta-feature-allowed-for-user"

def test_evaluate_per_person_denied():
    payload = {
        "capability_id": "beta.try",
        "context": {"person_id": "dave"}
    }
    r = client.post("/evaluate", json=payload)
    assert r.status_code == 200
    j = r.json()
    decision = j.get("decision", {})
    assert decision.get("allowed") is False
    assert decision.get("reason") == "beta-feature-not-allowed"
