import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Import the FastAPI app and helpers by adding src to path
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
import server as policy_server


class FakeRedis:
    def __init__(self):
        self._store = {}

    def setex(self, key, ttl, value):
        self._store[key] = value
        return True

    def exists(self, key):
        return 1 if key in self._store else 0

    def keys(self, pattern):
        # Very simple prefix match for 'revoked_grant:*'
        if pattern.endswith('*'):
            prefix = pattern[:-1]
            return [k for k in self._store.keys() if k.startswith(prefix)]
        return [k for k in self._store.keys() if k == pattern]


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    # Swap the redis client with a fake in the policy server module
    fake = FakeRedis()
    monkeypatch.setattr(policy_server, "redis_client", fake)
    yield fake


def test_create_and_introspect_grant_success():
    client = TestClient(policy_server.app)

    # Create grant
    payload = {
        "person_id": "person-123",
        "scopes": ["tierB.profile.read"],
        "purpose": "profile-export",
        "ttl_hours": 1,
        "metadata": {"source": "test"},
    }
    r = client.post("/grants", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert "grant_token" in body
    token = body["grant_token"]
    assert body["person_id"] == payload["person_id"]

    # Introspect should be active
    r2 = client.post("/grants/introspect", json={"token": token})
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["active"] is True
    assert b2["person_id"] == payload["person_id"]
    assert b2["purpose"] == payload["purpose"]


def test_revoke_grant_and_introspect_inactive():
    client = TestClient(policy_server.app)

    payload = {
        "person_id": "person-abc",
        "scopes": ["tierB.profile.read"],
        "purpose": "profile-export",
    }
    r = client.post("/grants", json=payload)
    assert r.status_code == 200
    body = r.json()
    token = body["grant_token"]
    jti = body["jti"]

    # Revoke by JTI
    r2 = client.post(f"/grants/{jti}/revoke")
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["revoked"] is True

    # Introspect should now be inactive
    r3 = client.post("/grants/introspect", json={"token": token})
    assert r3.status_code == 200
    b3 = r3.json()
    assert b3["active"] is False
    assert "Grant has been revoked" in b3.get("error", "")


def test_grant_stats_with_revocations(fake_redis):
    client = TestClient(policy_server.app)

    # Add two revoked keys
    fake_redis.setex("revoked_grant:one", 10, "revoked")
    fake_redis.setex("revoked_grant:two", 10, "revoked")

    r = client.get("/grants/stats")
    assert r.status_code == 200
    b = r.json()
    assert b["redis_connected"] is True
    assert b["revoked_grants"] >= 2


def test_introspect_invalid_token():
    client = TestClient(policy_server.app)

    # Clearly invalid token
    r = client.post("/grants/introspect", json={"token": "not-a-jwt"})
    assert r.status_code == 200
    b = r.json()
    assert b["active"] is False
    # Error message content may vary by JWT library; require non-empty error string
    assert isinstance(b.get("error"), str) and len(b.get("error")) > 0
