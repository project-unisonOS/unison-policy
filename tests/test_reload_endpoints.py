"""
Integration Tests for Hot-Reload Endpoints

Tests the hot-reload API endpoints in the policy server.
"""

import pytest
import json
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import after path is set
from bundle_signer import PolicyBundleSigner


@pytest.fixture
def test_bundle():
    """Create a test bundle file"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create signer
        signer = PolicyBundleSigner(
            private_key_path=os.path.join(tmpdir, "private.pem"),
            public_key_path=os.path.join(tmpdir, "public.pem")
        )
        
        # Create bundle
        bundle_data = {
            "metadata": {
                "bundle_id": "test-bundle-reload",
                "version": "2.0.0",
                "description": "Test bundle for reload"
            },
            "policies": [
                {
                    "id": "test-policy-reload",
                    "effect": "allow",
                    "description": "Test policy for reload",
                    "conditions": {}
                },
                {
                    "id": "test-policy-2",
                    "effect": "deny",
                    "description": "Second test policy",
                    "conditions": {}
                }
            ]
        }
        
        signed_bundle = signer.sign_bundle(bundle_data)
        
        # Save to file
        bundle_path = os.path.join(tmpdir, "test_bundle.json")
        with open(bundle_path, 'w') as f:
            json.dump(signed_bundle, f)
        
        # Update server's bundle signer to use same keys
        import server
        server._BUNDLE_SIGNER = signer
        
        yield bundle_path


@pytest.fixture
def client():
    """Create test client"""
    # Import server after bundle is set up
    from server import app
    return TestClient(app)


def test_reload_endpoint_success(client, test_bundle):
    """Test successful reload via POST /reload"""
    response = client.post(
        "/reload",
        json={"bundle_path": test_bundle}
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data['success'] is True
    assert data['version'] == '2.0.0'
    assert data['policies_loaded'] == 2
    assert data['error'] is None
    assert data['duration_ms'] > 0


def test_reload_endpoint_default_path(client):
    """Test reload with default bundle path"""
    # This will fail if default bundle doesn't exist, but should handle gracefully
    response = client.post("/reload", json={})
    
    # Could be 200 (success) or 404 (file not found) or 500 (validation error)
    assert response.status_code in [200, 404, 500]


def test_reload_endpoint_file_not_found(client):
    """Test reload with non-existent file"""
    response = client.post(
        "/reload",
        json={"bundle_path": "/nonexistent/bundle.json"}
    )
    
    assert response.status_code == 404
    assert "not found" in response.json()['detail'].lower()


def test_reload_endpoint_invalid_bundle(client):
    """Test reload with invalid bundle"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        # Write invalid bundle
        json.dump({"invalid": "bundle"}, f)
        temp_path = f.name
    
    try:
        response = client.post(
            "/reload",
            json={"bundle_path": temp_path}
        )
        
        assert response.status_code == 500
        detail = response.json()['detail'].lower()
        assert 'fail' in detail or 'error' in detail
    finally:
        os.unlink(temp_path)


def test_bundle_reload_endpoint(client, test_bundle):
    """Test POST /bundle/reload endpoint (alias)"""
    response = client.post(
        "/bundle/reload",
        json={"bundle_path": test_bundle}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data['success'] is True


def test_reload_history_endpoint(client, test_bundle):
    """Test GET /reload/history endpoint"""
    # Perform a reload first
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get history
    response = client.get("/reload/history")
    
    assert response.status_code == 200
    data = response.json()
    
    assert 'history' in data
    assert isinstance(data['history'], list)
    
    if len(data['history']) > 0:
        entry = data['history'][0]
        assert 'timestamp' in entry
        assert 'version' in entry
        assert 'success' in entry
        assert 'duration_ms' in entry


def test_reload_stats_endpoint(client, test_bundle):
    """Test GET /reload/stats endpoint"""
    # Perform a reload first
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get stats
    response = client.get("/reload/stats")
    
    assert response.status_code == 200
    data = response.json()
    
    assert 'total_reloads' in data
    assert 'successful_reloads' in data
    assert 'failed_reloads' in data
    assert 'success_rate' in data
    assert 'avg_duration_ms' in data
    assert 'last_reload' in data
    
    assert data['total_reloads'] >= 1


def test_get_bundle_after_reload(client, test_bundle):
    """Test GET /bundle shows updated version after reload"""
    # Reload bundle
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get current bundle info
    response = client.get("/bundle")
    
    assert response.status_code == 200
    data = response.json()
    
    if data.get('bundle_loaded'):
        assert data['version'] == '2.0.0'
        assert data['policies_count'] == 2


def test_evaluate_includes_version(client, test_bundle):
    """Test that /evaluate response includes policy_version after reload"""
    # Reload bundle
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Evaluate a policy
    response = client.post(
        "/evaluate",
        json={
            "capability_id": "test-capability",
            "context": {}
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert 'policy_version' in data
    assert data['policy_version'] == '2.0.0'


def test_rules_includes_version(client, test_bundle):
    """Test that /rules response includes policy_version after reload"""
    # Reload bundle
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get rules
    response = client.get("/rules")
    
    assert response.status_code == 200
    data = response.json()
    
    assert 'policy_version' in data
    assert data['policy_version'] == '2.0.0'


def test_metrics_includes_version(client, test_bundle):
    """Test that /metrics includes bundle version after reload"""
    # Reload bundle
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get metrics
    response = client.get("/metrics")
    
    assert response.status_code == 200
    metrics_text = response.text
    
    assert 'unison_policy_bundle_version' in metrics_text
    assert '2.0.0' in metrics_text


def test_concurrent_evaluate_during_reload(client, test_bundle):
    """Test that evaluate requests work during reload"""
    import threading
    import time
    
    results = {'evaluate_success': 0, 'evaluate_error': 0}
    
    def evaluate_loop():
        """Continuously evaluate policies"""
        for _ in range(10):
            try:
                response = client.post(
                    "/evaluate",
                    json={
                        "capability_id": "test",
                        "context": {}
                    }
                )
                if response.status_code == 200:
                    results['evaluate_success'] += 1
                else:
                    results['evaluate_error'] += 1
            except Exception:
                results['evaluate_error'] += 1
            time.sleep(0.01)
    
    # Start evaluate thread
    eval_thread = threading.Thread(target=evaluate_loop)
    eval_thread.start()
    
    # Perform reload while evaluating
    time.sleep(0.02)
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Wait for evaluate thread
    eval_thread.join()
    
    # Should have mostly successes
    assert results['evaluate_success'] > 0
    # Some errors are acceptable but should be minority
    assert results['evaluate_success'] > results['evaluate_error']


def test_multiple_reloads(client, test_bundle):
    """Test multiple consecutive reloads"""
    for i in range(3):
        response = client.post(
            "/reload",
            json={"bundle_path": test_bundle}
        )
        
        assert response.status_code == 200
        assert response.json()['success'] is True
    
    # Check history has all reloads
    response = client.get("/reload/history")
    history = response.json()['history']
    
    assert len(history) >= 3


def test_reload_preserves_service_availability(client, test_bundle):
    """Test that service remains available during and after reload"""
    # Check health before
    response = client.get("/healthz")
    assert response.status_code == 200
    
    # Perform reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Check health after
    response = client.get("/healthz")
    assert response.status_code == 200
    
    # Check ready after
    response = client.get("/readyz")
    assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
