"""
Tests for Hot-Reload Metrics

Tests the Prometheus metrics for hot-reload functionality.
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

from bundle_signer import PolicyBundleSigner


def extract_metric_value(metrics_text: str, metric_name: str):
    """Extract a metric value from Prometheus text format"""
    for line in metrics_text.split('\n'):
        if metric_name in line and not line.startswith('#'):
            parts = line.split()
            if len(parts) == 2:  # metric_name value
                # Try to parse as number
                try:
                    if '.' in parts[1]:
                        return float(parts[1])
                    else:
                        return int(parts[1])
                except ValueError:
                    pass
            elif len(parts) >= 2:  # metric_name{labels} value
                # Try to parse as number
                try:
                    if '.' in parts[-1]:
                        return float(parts[-1])
                    else:
                        return int(parts[-1])
                except ValueError:
                    pass
    return None


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
                "bundle_id": "test-metrics-bundle",
                "version": "3.0.0",
                "description": "Test bundle for metrics"
            },
            "policies": [
                {
                    "id": "test-policy-metrics",
                    "effect": "allow",
                    "description": "Test policy",
                    "conditions": {}
                }
            ]
        }
        
        signed_bundle = signer.sign_bundle(bundle_data)
        
        # Save to file
        bundle_path = os.path.join(tmpdir, "test_bundle.json")
        with open(bundle_path, 'w') as f:
            json.dump(signed_bundle, f)
        
        # Update server's bundle signer
        import server
        server._BUNDLE_SIGNER = signer
        
        yield bundle_path


@pytest.fixture
def client():
    """Create test client"""
    from server import app
    return TestClient(app)


def test_metrics_includes_reload_counters(client, test_bundle):
    """Test that /metrics includes reload counters"""
    # Perform a reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get metrics
    response = client.get("/metrics")
    assert response.status_code == 200
    
    metrics_text = response.text
    
    # Check for reload metrics
    assert "unison_policy_reload_total" in metrics_text
    assert "unison_policy_reload_success_total" in metrics_text
    assert "unison_policy_reload_failure_total" in metrics_text
    assert "unison_policy_reload_success_rate" in metrics_text
    assert "unison_policy_reload_duration_seconds" in metrics_text


def test_metrics_reload_total_increments(client, test_bundle):
    """Test that reload_total metric exists and tracks reloads"""
    # Perform reload
    response = client.post("/reload", json={"bundle_path": test_bundle})
    assert response.status_code == 200
    
    # Get metrics
    response = client.get("/metrics")
    reload_total = extract_metric_value(response.text, 'unison_policy_reload_total')
    
    # Should exist and be >= 1 (at least one reload)
    assert reload_total is not None, "reload_total metric not found"
    assert reload_total >= 1


def test_metrics_success_counter_increments(client, test_bundle):
    """Test that success counter increments on successful reload"""
    # Perform successful reload
    response = client.post("/reload", json={"bundle_path": test_bundle})
    assert response.status_code == 200
    
    # Get metrics
    response = client.get("/metrics")
    metrics_text = response.text
    
    # Extract value
    success_total = extract_metric_value(metrics_text, 'unison_policy_reload_success_total')
    
    # Should have at least one success
    assert success_total is not None
    assert success_total >= 1


def test_metrics_failure_counter_increments(client):
    """Test that failure counter exists and can increment"""
    # Attempt failed reload (non-existent file)
    response = client.post("/reload", json={"bundle_path": "/nonexistent/bundle.json"})
    # Should return 404
    assert response.status_code == 404
    
    # Get metrics
    response = client.get("/metrics")
    metrics_text = response.text
    
    # Check that failure counter exists
    assert "unison_policy_reload_failure_total" in metrics_text


def test_metrics_success_rate_calculation(client, test_bundle):
    """Test that success rate metric exists"""
    # Perform successful reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get metrics
    response = client.get("/metrics")
    metrics_text = response.text
    
    # Check that success rate exists
    assert "unison_policy_reload_success_rate" in metrics_text
    
    # Extract success rate
    success_rate = extract_metric_value(metrics_text, 'unison_policy_reload_success_rate')
    
    # Should exist and be between 0 and 100
    assert success_rate is not None
    assert 0 <= success_rate <= 100


def test_metrics_duration_tracking(client, test_bundle):
    """Test that reload duration is tracked"""
    # Perform reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get metrics
    response = client.get("/metrics")
    metrics_text = response.text
    
    # Check that duration metric exists
    assert "unison_policy_reload_duration_seconds" in metrics_text
    
    # Extract duration
    duration = extract_metric_value(metrics_text, 'unison_policy_reload_duration_seconds')
    
    # Should exist and be reasonable
    assert duration is not None
    assert duration >= 0
    assert duration < 10  # Should complete in < 10 seconds


def test_metrics_bundle_version(client, test_bundle):
    """Test that bundle version is in metrics"""
    # Perform reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get metrics
    response = client.get("/metrics")
    metrics_text = response.text
    
    # Check for version
    assert "unison_policy_bundle_version" in metrics_text
    assert "3.0.0" in metrics_text


def test_metrics_bundle_loaded_timestamp(client, test_bundle):
    """Test that bundle loaded timestamp is in metrics"""
    # Perform reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get metrics
    response = client.get("/metrics")
    metrics_text = response.text
    
    # Check for timestamp
    assert "unison_policy_bundle_loaded_timestamp" in metrics_text
    
    # Extract timestamp
    timestamp = extract_metric_value(metrics_text, 'unison_policy_bundle_loaded_timestamp')
    
    # Should exist and be a reasonable Unix timestamp (> 2020-01-01)
    assert timestamp is not None
    assert timestamp > 1577836800


def test_readyz_includes_bundle_info(client, test_bundle):
    """Test that /readyz includes bundle version and age"""
    # Perform reload
    client.post("/reload", json={"bundle_path": test_bundle})
    
    # Get readyz
    response = client.get("/readyz")
    assert response.status_code == 200
    
    data = response.json()
    
    # Check for bundle info
    assert "bundle_version" in data
    assert data["bundle_version"] == "3.0.0"
    assert "bundle_loaded_at" in data
    assert "bundle_age_hours" in data
    assert "bundle_stale" in data
    
    # Bundle should not be stale (just loaded)
    assert data["bundle_stale"] is False
    
    # Age should be very small
    if data["bundle_age_hours"] is not None:
        assert data["bundle_age_hours"] < 1


def test_readyz_staleness_check(client):
    """Test that readyz reports bundle staleness"""
    # Get readyz
    response = client.get("/readyz")
    assert response.status_code == 200
    
    data = response.json()
    
    # Should have staleness field
    assert "bundle_stale" in data
    # Value should be boolean
    assert isinstance(data["bundle_stale"], bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
