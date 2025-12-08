import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure src is importable when running in isolation
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import server  # noqa: E402


@pytest.fixture(autouse=True)
def reset_rules():
    # ensure default rules are in place
    server._set_rules([])
    yield
    server._set_rules([])


def test_action_envelope_device_class_rule():
    client = TestClient(server.app)
    server._set_rules(
        [
            {
                "match": {"target": {"device_class": "robot"}},
                "decision": {"action": "deny", "reason": "no-robots"},
            }
        ]
    )

    context = {
        "action_envelope": {
            "person_id": "person-1",
            "target": {"device_id": "r1", "device_class": "robot"},
            "intent": {"name": "robot.move", "parameters": {}},
            "risk_level": "medium",
        }
    }
    eval_resp = client.post("/evaluate", json={"capability_id": "proposed_action", "context": context})
    assert eval_resp.status_code == 200
    decision = eval_resp.json()["decision"]
    assert decision["allowed"] is False
    assert decision["reason"] == "no-robots"
