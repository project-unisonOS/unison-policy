"""
Hot-Reload Module for Policy Bundles

Provides atomic hot-reload functionality for policy bundles with:
- Thread-safe atomic swaps
- Validation before reload
- Automatic rollback on failure
- Reload history tracking
"""

import time
import threading
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from bundle_signer import PolicyBundleSigner

logger = logging.getLogger("unison-policy")

# Thread lock for atomic operations
_RELOAD_LOCK = threading.Lock()

# Reload history (last 10 reloads)
_RELOAD_HISTORY: List[Dict[str, Any]] = []
MAX_HISTORY_SIZE = 10


def validate_bundle(bundle: Dict[str, Any]) -> None:
    """
    Validate a policy bundle before loading
    
    Args:
        bundle: Bundle data to validate
        
    Raises:
        ValueError: If bundle is invalid
    """
    # Check bundle structure
    if not isinstance(bundle, dict):
        raise ValueError("Bundle must be a dictionary")
    
    # Check metadata
    metadata = bundle.get('metadata')
    if not metadata:
        raise ValueError("Bundle missing metadata")
    
    if not isinstance(metadata, dict):
        raise ValueError("Bundle metadata must be a dictionary")
    
    # Check required metadata fields
    required_fields = ['bundle_id', 'version', 'issued_at']
    for field in required_fields:
        if field not in metadata:
            raise ValueError(f"Bundle metadata missing required field: {field}")
    
    # Check policies
    policies = bundle.get('policies')
    if policies is None:
        raise ValueError("Bundle missing policies field")
    
    if not isinstance(policies, list):
        raise ValueError("Bundle policies must be a list")
    
    if len(policies) == 0:
        raise ValueError("Bundle contains no policies")
    
    # Validate each policy has required fields
    for i, policy in enumerate(policies):
        if not isinstance(policy, dict):
            raise ValueError(f"Policy {i} is not a dictionary")
        
        if 'id' not in policy:
            raise ValueError(f"Policy {i} missing 'id' field")
        
        if 'effect' not in policy:
            raise ValueError(f"Policy {i} missing 'effect' field")
    
    # Check signature
    signature = bundle.get('signature')
    if not signature:
        raise ValueError("Bundle missing signature")
    
    if not isinstance(signature, dict):
        raise ValueError("Bundle signature must be a dictionary")
    
    logger.info(f"Bundle validation passed: {len(policies)} policies")


def hot_reload_bundle(
    bundle_path: str,
    bundle_signer: PolicyBundleSigner,
    load_bundle_func,
    load_policies_func,
    current_bundle_ref: Dict[str, Any],
    current_rules_ref: List[Dict[str, Any]],
    current_version_ref: Dict[str, str]
) -> Dict[str, Any]:
    """
    Atomically reload policy bundle
    
    Args:
        bundle_path: Path to bundle file
        bundle_signer: Bundle signer instance
        load_bundle_func: Function to load bundle from file
        load_policies_func: Function to extract policies from bundle
        current_bundle_ref: Reference dict with 'value' key for current bundle
        current_rules_ref: Reference dict with 'value' key for current rules
        current_version_ref: Reference dict with 'value' key for current version
        
    Returns:
        {
            "success": bool,
            "version": str,
            "duration_ms": float,
            "policies_loaded": int,
            "error": str | None
        }
    """
    start_time = time.time()
    
    try:
        # Load new bundle (outside lock to minimize lock time)
        logger.info(f"Loading bundle from {bundle_path}")
        new_bundle = load_bundle_func(bundle_path)
        
        if not new_bundle:
            raise ValueError("Failed to load bundle from file")
        
        # Validate bundle (outside lock)
        logger.info("Validating bundle")
        validate_bundle(new_bundle)
        
        # Verify signature (outside lock)
        logger.info("Verifying bundle signature")
        if not bundle_signer.verify_bundle(new_bundle):
            raise ValueError("Bundle signature verification failed")
        
        # Extract policies (outside lock)
        logger.info("Extracting policies from bundle")
        new_policies = load_policies_func(new_bundle)
        
        if not new_policies:
            raise ValueError("Bundle contains no valid policies")
        
        new_version = new_bundle.get('metadata', {}).get('version', '0.0.0')
        
        # Atomic swap (inside lock - should be very fast)
        with _RELOAD_LOCK:
            # Save old state for rollback
            old_bundle = current_bundle_ref.get('value')
            old_rules = current_rules_ref.get('value')
            old_version = current_version_ref.get('value', '0.0.0')
            
            try:
                # Swap to new state
                current_bundle_ref['value'] = new_bundle
                current_rules_ref['value'] = new_policies
                current_version_ref['value'] = new_version
                current_version_ref['loaded_at'] = datetime.now(timezone.utc).isoformat()
                
                duration_ms = (time.time() - start_time) * 1000
                
                # Record success
                _add_reload_history({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": new_version,
                    "success": True,
                    "duration_ms": round(duration_ms, 2),
                    "policies_loaded": len(new_policies),
                    "error": None
                })
                
                logger.info(f"✅ Hot-reload successful: v{new_version} ({duration_ms:.2f}ms, {len(new_policies)} policies)")
                
                return {
                    "success": True,
                    "version": new_version,
                    "duration_ms": round(duration_ms, 2),
                    "policies_loaded": len(new_policies),
                    "error": None
                }
                
            except Exception as e:
                # Rollback on failure
                logger.error(f"Rollback triggered during swap: {e}")
                current_bundle_ref['value'] = old_bundle
                current_rules_ref['value'] = old_rules
                current_version_ref['value'] = old_version
                raise
                
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        error_msg = str(e)
        
        # Record failure
        _add_reload_history({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": None,
            "success": False,
            "duration_ms": round(duration_ms, 2),
            "policies_loaded": 0,
            "error": error_msg
        })
        
        logger.error(f"❌ Hot-reload failed: {error_msg} ({duration_ms:.2f}ms)")
        
        return {
            "success": False,
            "version": current_version_ref.get('value', '0.0.0'),
            "duration_ms": round(duration_ms, 2),
            "policies_loaded": 0,
            "error": error_msg
        }


def _add_reload_history(entry: Dict[str, Any]) -> None:
    """Add entry to reload history, maintaining max size"""
    _RELOAD_HISTORY.append(entry)
    
    # Keep only last MAX_HISTORY_SIZE entries
    if len(_RELOAD_HISTORY) > MAX_HISTORY_SIZE:
        _RELOAD_HISTORY.pop(0)


def get_reload_history() -> List[Dict[str, Any]]:
    """Get reload history (most recent first)"""
    return list(reversed(_RELOAD_HISTORY))


def get_reload_stats() -> Dict[str, Any]:
    """Get reload statistics"""
    if not _RELOAD_HISTORY:
        return {
            "total_reloads": 0,
            "successful_reloads": 0,
            "failed_reloads": 0,
            "success_rate": 0.0,
            "avg_duration_ms": 0.0,
            "last_reload": None
        }
    
    total = len(_RELOAD_HISTORY)
    successful = sum(1 for entry in _RELOAD_HISTORY if entry['success'])
    failed = total - successful
    success_rate = (successful / total * 100) if total > 0 else 0.0
    
    durations = [entry['duration_ms'] for entry in _RELOAD_HISTORY]
    avg_duration = sum(durations) / len(durations) if durations else 0.0
    
    last_reload = _RELOAD_HISTORY[-1] if _RELOAD_HISTORY else None
    
    return {
        "total_reloads": total,
        "successful_reloads": successful,
        "failed_reloads": failed,
        "success_rate": round(success_rate, 2),
        "avg_duration_ms": round(avg_duration, 2),
        "last_reload": last_reload
    }
