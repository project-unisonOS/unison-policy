"""
Tests for Hot-Reload Functionality

Tests the atomic hot-reload mechanism for policy bundles.
"""

import pytest
import json
import os
import time
import tempfile
import threading
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from hot_reload import (
    validate_bundle,
    hot_reload_bundle,
    get_reload_history,
    get_reload_stats,
    _add_reload_history
)
from bundle_signer import PolicyBundleSigner


@pytest.fixture
def bundle_signer():
    """Create a bundle signer for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        signer = PolicyBundleSigner(
            private_key_path=os.path.join(tmpdir, "private.pem"),
            public_key_path=os.path.join(tmpdir, "public.pem")
        )
        yield signer


@pytest.fixture
def valid_bundle(bundle_signer):
    """Create a valid signed bundle"""
    bundle_data = {
        "metadata": {
            "bundle_id": "test-bundle-1",
            "version": "1.0.0",
            "description": "Test bundle"
        },
        "policies": [
            {
                "id": "test-policy-1",
                "effect": "allow",
                "description": "Test policy",
                "conditions": {}
            }
        ]
    }
    return bundle_signer.sign_bundle(bundle_data)


@pytest.fixture
def invalid_bundle():
    """Create an invalid bundle (missing required fields)"""
    return {
        "metadata": {
            "bundle_id": "invalid-bundle"
            # Missing version and issued_at
        },
        "policies": []  # Empty policies
    }


@pytest.fixture
def temp_bundle_file(valid_bundle):
    """Create a temporary bundle file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(valid_bundle, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


# --- Validation Tests ---

def test_validate_bundle_success(valid_bundle):
    """Test that a valid bundle passes validation"""
    # Should not raise
    validate_bundle(valid_bundle)


def test_validate_bundle_not_dict():
    """Test validation fails for non-dict bundle"""
    with pytest.raises(ValueError, match="Bundle must be a dictionary"):
        validate_bundle("not a dict")


def test_validate_bundle_missing_metadata():
    """Test validation fails for missing metadata"""
    bundle = {"policies": []}
    with pytest.raises(ValueError, match="Bundle missing metadata"):
        validate_bundle(bundle)


def test_validate_bundle_metadata_not_dict():
    """Test validation fails for non-dict metadata"""
    bundle = {"metadata": "not a dict", "policies": []}
    with pytest.raises(ValueError, match="Bundle metadata must be a dictionary"):
        validate_bundle(bundle)


def test_validate_bundle_missing_required_fields():
    """Test validation fails for missing required metadata fields"""
    bundle = {
        "metadata": {
            "bundle_id": "test"
            # Missing version and issued_at
        },
        "policies": []
    }
    with pytest.raises(ValueError, match="missing required field"):
        validate_bundle(bundle)


def test_validate_bundle_missing_policies():
    """Test validation fails for missing policies field"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        }
    }
    with pytest.raises(ValueError, match="Bundle missing policies field"):
        validate_bundle(bundle)


def test_validate_bundle_policies_not_list():
    """Test validation fails for non-list policies"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": "not a list"
    }
    with pytest.raises(ValueError, match="Bundle policies must be a list"):
        validate_bundle(bundle)


def test_validate_bundle_empty_policies():
    """Test validation fails for empty policies"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": [],
        "signature": {"algorithm": "test"}
    }
    with pytest.raises(ValueError, match="Bundle contains no policies"):
        validate_bundle(bundle)


def test_validate_bundle_policy_not_dict():
    """Test validation fails for non-dict policy"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": ["not a dict"],
        "signature": {"algorithm": "test"}
    }
    with pytest.raises(ValueError, match="Policy 0 is not a dictionary"):
        validate_bundle(bundle)


def test_validate_bundle_policy_missing_id():
    """Test validation fails for policy missing id"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": [{"effect": "allow"}],
        "signature": {"algorithm": "test"}
    }
    with pytest.raises(ValueError, match="Policy 0 missing 'id' field"):
        validate_bundle(bundle)


def test_validate_bundle_policy_missing_effect():
    """Test validation fails for policy missing effect"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": [{"id": "test-policy"}],
        "signature": {"algorithm": "test"}
    }
    with pytest.raises(ValueError, match="Policy 0 missing 'effect' field"):
        validate_bundle(bundle)


def test_validate_bundle_missing_signature():
    """Test validation fails for missing signature"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": [{"id": "test", "effect": "allow"}]
    }
    with pytest.raises(ValueError, match="Bundle missing signature"):
        validate_bundle(bundle)


def test_validate_bundle_signature_not_dict():
    """Test validation fails for non-dict signature"""
    bundle = {
        "metadata": {
            "bundle_id": "test",
            "version": "1.0.0",
            "issued_at": "2025-01-01T00:00:00Z"
        },
        "policies": [{"id": "test", "effect": "allow"}],
        "signature": "not a dict"
    }
    with pytest.raises(ValueError, match="Bundle signature must be a dictionary"):
        validate_bundle(bundle)


# --- Hot-Reload Tests ---

def test_hot_reload_success(temp_bundle_file, bundle_signer):
    """Test successful hot-reload"""
    # Setup references
    bundle_ref = {'value': None}
    rules_ref = {'value': []}
    version_ref = {'value': '0.0.0', 'loaded_at': None}
    
    def load_bundle_func(path):
        with open(path, 'r') as f:
            return json.load(f)
    
    def load_policies_func(bundle):
        return bundle.get('policies', [])
    
    # Perform reload
    result = hot_reload_bundle(
        bundle_path=temp_bundle_file,
        bundle_signer=bundle_signer,
        load_bundle_func=load_bundle_func,
        load_policies_func=load_policies_func,
        current_bundle_ref=bundle_ref,
        current_rules_ref=rules_ref,
        current_version_ref=version_ref
    )
    
    # Verify success
    assert result['success'] is True
    assert result['version'] == '1.0.0'
    assert result['policies_loaded'] == 1
    assert result['error'] is None
    assert result['duration_ms'] > 0
    assert result['duration_ms'] < 1000  # Should be fast
    
    # Verify state was updated
    assert bundle_ref['value'] is not None
    assert len(rules_ref['value']) == 1
    assert version_ref['value'] == '1.0.0'
    assert version_ref['loaded_at'] is not None


def test_hot_reload_timing(temp_bundle_file, bundle_signer):
    """Test that hot-reload completes quickly (< 100ms target)"""
    bundle_ref = {'value': None}
    rules_ref = {'value': []}
    version_ref = {'value': '0.0.0', 'loaded_at': None}
    
    def load_bundle_func(path):
        with open(path, 'r') as f:
            return json.load(f)
    
    def load_policies_func(bundle):
        return bundle.get('policies', [])
    
    result = hot_reload_bundle(
        bundle_path=temp_bundle_file,
        bundle_signer=bundle_signer,
        load_bundle_func=load_bundle_func,
        load_policies_func=load_policies_func,
        current_bundle_ref=bundle_ref,
        current_rules_ref=rules_ref,
        current_version_ref=version_ref
    )
    
    # Check timing (may be > 100ms on slow systems, but should be reasonable)
    assert result['duration_ms'] < 1000, f"Reload took {result['duration_ms']}ms (target < 100ms)"


def test_hot_reload_file_not_found(bundle_signer):
    """Test hot-reload fails gracefully for missing file"""
    bundle_ref = {'value': None}
    rules_ref = {'value': []}
    version_ref = {'value': '0.0.0', 'loaded_at': None}
    
    def load_bundle_func(path):
        return None  # Simulate file not found
    
    def load_policies_func(bundle):
        return bundle.get('policies', [])
    
    result = hot_reload_bundle(
        bundle_path="/nonexistent/bundle.json",
        bundle_signer=bundle_signer,
        load_bundle_func=load_bundle_func,
        load_policies_func=load_policies_func,
        current_bundle_ref=bundle_ref,
        current_rules_ref=rules_ref,
        current_version_ref=version_ref
    )
    
    # Verify failure
    assert result['success'] is False
    assert result['error'] is not None
    assert 'Failed to load bundle' in result['error']
    
    # Verify state was NOT updated
    assert bundle_ref['value'] is None
    assert rules_ref['value'] == []
    assert version_ref['value'] == '0.0.0'


def test_hot_reload_invalid_bundle(temp_bundle_file, bundle_signer):
    """Test hot-reload fails for invalid bundle"""
    bundle_ref = {'value': None}
    rules_ref = {'value': []}
    version_ref = {'value': '0.0.0', 'loaded_at': None}
    
    def load_bundle_func(path):
        # Return invalid bundle
        return {
            "metadata": {"bundle_id": "test"},
            "policies": []  # Empty
        }
    
    def load_policies_func(bundle):
        return bundle.get('policies', [])
    
    result = hot_reload_bundle(
        bundle_path=temp_bundle_file,
        bundle_signer=bundle_signer,
        load_bundle_func=load_bundle_func,
        load_policies_func=load_policies_func,
        current_bundle_ref=bundle_ref,
        current_rules_ref=rules_ref,
        current_version_ref=version_ref
    )
    
    # Verify failure
    assert result['success'] is False
    assert result['error'] is not None
    
    # Verify state was NOT updated
    assert bundle_ref['value'] is None


def test_hot_reload_signature_verification_failure(temp_bundle_file):
    """Test hot-reload fails for signature verification failure"""
    # Create a different signer (different keys)
    with tempfile.TemporaryDirectory() as tmpdir:
        wrong_signer = PolicyBundleSigner(
            private_key_path=os.path.join(tmpdir, "wrong_private.pem"),
            public_key_path=os.path.join(tmpdir, "wrong_public.pem")
        )
        
        bundle_ref = {'value': None}
        rules_ref = {'value': []}
        version_ref = {'value': '0.0.0', 'loaded_at': None}
        
        def load_bundle_func(path):
            with open(path, 'r') as f:
                return json.load(f)
        
        def load_policies_func(bundle):
            return bundle.get('policies', [])
        
        result = hot_reload_bundle(
            bundle_path=temp_bundle_file,
            bundle_signer=wrong_signer,  # Wrong signer
            load_bundle_func=load_bundle_func,
            load_policies_func=load_policies_func,
            current_bundle_ref=bundle_ref,
            current_rules_ref=rules_ref,
            current_version_ref=version_ref
        )
        
        # Verify failure
        assert result['success'] is False
        assert 'verification failed' in result['error'].lower()


def test_hot_reload_rollback_on_failure(temp_bundle_file, bundle_signer):
    """Test that hot-reload rolls back state on failure"""
    # Setup initial state
    initial_bundle = {"metadata": {"version": "0.5.0"}, "policies": [{"id": "old", "effect": "allow"}]}
    initial_rules = [{"old": "rule"}]
    
    bundle_ref = {'value': initial_bundle}
    rules_ref = {'value': initial_rules}
    version_ref = {'value': '0.5.0', 'loaded_at': '2025-01-01T00:00:00Z'}
    
    def load_bundle_func(path):
        with open(path, 'r') as f:
            return json.load(f)
    
    def load_policies_func(bundle):
        # Simulate failure during policy extraction
        raise ValueError("Policy extraction failed")
    
    result = hot_reload_bundle(
        bundle_path=temp_bundle_file,
        bundle_signer=bundle_signer,
        load_bundle_func=load_bundle_func,
        load_policies_func=load_policies_func,
        current_bundle_ref=bundle_ref,
        current_rules_ref=rules_ref,
        current_version_ref=version_ref
    )
    
    # Verify failure
    assert result['success'] is False
    
    # Verify state was rolled back (unchanged)
    assert bundle_ref['value'] == initial_bundle
    assert rules_ref['value'] == initial_rules
    assert version_ref['value'] == '0.5.0'


def test_hot_reload_concurrent_requests(temp_bundle_file, bundle_signer):
    """Test that hot-reload is thread-safe during concurrent requests"""
    bundle_ref = {'value': None}
    rules_ref = {'value': []}
    version_ref = {'value': '0.0.0', 'loaded_at': None}
    
    def load_bundle_func(path):
        with open(path, 'r') as f:
            return json.load(f)
    
    def load_policies_func(bundle):
        # Simulate some processing time
        time.sleep(0.01)
        return bundle.get('policies', [])
    
    # Perform reload in background
    reload_thread = threading.Thread(
        target=hot_reload_bundle,
        args=(
            temp_bundle_file,
            bundle_signer,
            load_bundle_func,
            load_policies_func,
            bundle_ref,
            rules_ref,
            version_ref
        )
    )
    reload_thread.start()
    
    # Simulate concurrent access to rules
    access_count = 0
    for _ in range(100):
        rules = rules_ref['value']
        if rules is not None:
            access_count += 1
        time.sleep(0.0001)
    
    reload_thread.join()
    
    # Verify reload succeeded
    assert version_ref['value'] == '1.0.0'
    # Verify we could access rules during reload
    assert access_count > 0


# --- History and Stats Tests ---

def test_reload_history_tracking():
    """Test that reload history is tracked correctly"""
    # Clear history
    from hot_reload import _RELOAD_HISTORY
    _RELOAD_HISTORY.clear()
    
    # Add some entries
    _add_reload_history({
        "timestamp": "2025-01-01T00:00:00Z",
        "version": "1.0.0",
        "success": True,
        "duration_ms": 50.0,
        "policies_loaded": 5,
        "error": None
    })
    
    _add_reload_history({
        "timestamp": "2025-01-01T00:01:00Z",
        "version": None,
        "success": False,
        "duration_ms": 25.0,
        "policies_loaded": 0,
        "error": "Test error"
    })
    
    history = get_reload_history()
    
    # Verify history (most recent first)
    assert len(history) == 2
    assert history[0]['success'] is False  # Most recent
    assert history[1]['success'] is True


def test_reload_history_max_size():
    """Test that reload history maintains max size"""
    from hot_reload import _RELOAD_HISTORY, MAX_HISTORY_SIZE
    _RELOAD_HISTORY.clear()
    
    # Add more than MAX_HISTORY_SIZE entries
    for i in range(MAX_HISTORY_SIZE + 5):
        _add_reload_history({
            "timestamp": f"2025-01-01T00:{i:02d}:00Z",
            "version": f"1.0.{i}",
            "success": True,
            "duration_ms": 50.0,
            "policies_loaded": 1,
            "error": None
        })
    
    history = get_reload_history()
    
    # Verify only MAX_HISTORY_SIZE entries kept
    assert len(history) == MAX_HISTORY_SIZE
    # Verify most recent entries kept
    assert history[0]['version'] == f"1.0.{MAX_HISTORY_SIZE + 4}"


def test_reload_stats_empty():
    """Test reload stats with no history"""
    from hot_reload import _RELOAD_HISTORY
    _RELOAD_HISTORY.clear()
    
    stats = get_reload_stats()
    
    assert stats['total_reloads'] == 0
    assert stats['successful_reloads'] == 0
    assert stats['failed_reloads'] == 0
    assert stats['success_rate'] == 0.0
    assert stats['avg_duration_ms'] == 0.0
    assert stats['last_reload'] is None


def test_reload_stats_with_history():
    """Test reload stats calculation"""
    from hot_reload import _RELOAD_HISTORY
    _RELOAD_HISTORY.clear()
    
    # Add mixed success/failure entries
    _add_reload_history({
        "timestamp": "2025-01-01T00:00:00Z",
        "version": "1.0.0",
        "success": True,
        "duration_ms": 50.0,
        "policies_loaded": 5,
        "error": None
    })
    
    _add_reload_history({
        "timestamp": "2025-01-01T00:01:00Z",
        "version": "1.0.1",
        "success": True,
        "duration_ms": 60.0,
        "policies_loaded": 5,
        "error": None
    })
    
    _add_reload_history({
        "timestamp": "2025-01-01T00:02:00Z",
        "version": None,
        "success": False,
        "duration_ms": 25.0,
        "policies_loaded": 0,
        "error": "Test error"
    })
    
    stats = get_reload_stats()
    
    assert stats['total_reloads'] == 3
    assert stats['successful_reloads'] == 2
    assert stats['failed_reloads'] == 1
    assert stats['success_rate'] == 66.67
    assert stats['avg_duration_ms'] == 45.0  # (50 + 60 + 25) / 3
    assert stats['last_reload']['success'] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
