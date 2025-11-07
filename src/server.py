from fastapi import FastAPI, Request, Body, HTTPException
from fastapi import Body
import uvicorn
import logging
import json
import time
import os
from typing import Any, Dict, List, Optional
import yaml
from datetime import datetime, timezone
from unison_common.logging import configure_logging, log_json
from collections import defaultdict
from bundle_signer import PolicyBundleSigner
from hot_reload import hot_reload_bundle, get_reload_history, get_reload_stats

app = FastAPI(title="unison-policy")

logger = configure_logging("unison-policy")

# Simple in-memory metrics
_metrics = defaultdict(int)
_start_time = time.time()

RULES_PATH = os.getenv("UNISON_POLICY_RULES", "rules.yaml")
BUNDLE_PATH = os.getenv("UNISON_POLICY_BUNDLE", "bundle.signed.json")

# Use reference dictionaries for hot-reload compatibility
_BUNDLE_REF = {'value': None}  # Current bundle
_RULES_REF = {'value': []}  # Current rules
_VERSION_REF = {'value': '0.0.0', 'loaded_at': None}  # Current version and load time
_BUNDLE_SIGNER = None

# Convenience accessors (for backward compatibility)
def _get_current_bundle(): return _BUNDLE_REF['value']
def _get_current_rules(): return _RULES_REF['value']
def _get_current_version(): return _VERSION_REF['value']
def _get_loaded_at(): return _VERSION_REF.get('loaded_at')

def load_rules(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
            if isinstance(data, list):
                return data
    except Exception as e:
        logger.exception("failed_to_load_rules: %s", e)
    return []

# Initialize with YAML rules as fallback
_RULES_REF['value'] = load_rules(RULES_PATH)

def load_bundle(path: str) -> Optional[Dict[str, Any]]:
    """Load and verify a signed policy bundle"""
    if not os.path.exists(path):
        logger.info(f"Bundle file not found: {path}")
        return None
    
    try:
        # Initialize bundle signer
        global _BUNDLE_SIGNER
        if _BUNDLE_SIGNER is None:
            _BUNDLE_SIGNER = PolicyBundleSigner()
        
        # Load bundle
        bundle = _BUNDLE_SIGNER.load_bundle(path)
        
        # Verify signature
        if _BUNDLE_SIGNER.verify_bundle(bundle):
            logger.info(f"Loaded and verified bundle: {bundle.get('metadata', {}).get('bundle_id', 'unknown')}")
            return bundle
        else:
            logger.error(f"Bundle verification failed: {path}")
            return None
            
    except Exception as e:
        logger.exception(f"Failed to load bundle {path}: {e}")
        return None

def load_policies_from_bundle(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract policies from a verified bundle"""
    policies = bundle.get('policies', [])
    
    # Convert new policy format to legacy rule format for compatibility
    rules = []
    for policy in policies:
        rule = {
            "match": {
                "intent_prefix": policy.get("id"),
                "auth_scope": None,
                "safety_context": {
                    "data_classification": policy.get("conditions", {}).get("data_classification")
                },
                "time_window": policy.get("conditions", {}).get("time_restrictions", {}),
                "persons": None
            },
            "decision": {
                "action": policy.get("effect", "allow"),
                "reason": policy.get("description", f"policy:{policy.get('id', 'unknown')}"),
                "suggested_alternative": None
            }
        }
        rules.append(rule)
    
    return rules

# Initialize bundle signer
if _BUNDLE_SIGNER is None:
    _BUNDLE_SIGNER = PolicyBundleSigner()

# Initialize bundle if available
bundle = load_bundle(BUNDLE_PATH)
if bundle:
    _BUNDLE_REF['value'] = bundle
    _RULES_REF['value'] = load_policies_from_bundle(bundle)
    _VERSION_REF['value'] = bundle.get('metadata', {}).get('version', '0.0.0')
    _VERSION_REF['loaded_at'] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Loaded {len(_RULES_REF['value'])} policies from signed bundle v{_VERSION_REF['value']}")
else:
    logger.info(f"Using {len(_RULES_REF['value'])} rules from YAML file")

def _time_in_window(start: str, end: str) -> bool:
    """Return True if current UTC time is within HH:MM window (inclusive)."""
    try:
        now = datetime.now(timezone.utc)
        current = now.hour * 60 + now.minute
        start_h, start_m = map(int, start.split(":"))
        end_h, end_m = map(int, end.split(":"))
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        if start_minutes <= end_minutes:
            return start_minutes <= current <= end_minutes
        else:  # crosses midnight
            return current >= start_minutes or current <= end_minutes
    except Exception:
        return False

def _matches_persons(persons: List[str], person_id: str) -> bool:
    """Return True if person_id is in the allowed list."""
    return isinstance(persons, list) and person_id in persons

@app.get("/healthz")
@app.get("/health")
def health(request: Request):
    _metrics["/health"] += 1
    event_id = request.headers.get("X-Event-ID")
    log_json(logging.INFO, "health", service="unison-policy", event_id=event_id)
    return {"status": "ok", "service": "unison-policy"}

@app.get("/metrics")
def metrics():
    """Prometheus text-format metrics."""
    uptime = time.time() - _start_time
    
    # Get reload stats
    reload_stats = get_reload_stats()
    
    lines = [
        "# HELP unison_policy_requests_total Total number of requests by endpoint",
        "# TYPE unison_policy_requests_total counter",
    ]
    for k, v in _metrics.items():
        lines.append(f'unison_policy_requests_total{{endpoint="{k}"}} {v}')
    
    lines.extend([
        "",
        "# HELP unison_policy_uptime_seconds Service uptime in seconds",
        "# TYPE unison_policy_uptime_seconds gauge",
        f"unison_policy_uptime_seconds {uptime}",
        "",
        "# HELP unison_policy_rules_loaded Number of loaded policy rules",
        "# TYPE unison_policy_rules_loaded gauge",
        f"unison_policy_rules_loaded {len(_get_current_rules())}",
        "",
        "# HELP unison_policy_bundle_version Current policy bundle version",
        "# TYPE unison_policy_bundle_version gauge",
        f'unison_policy_bundle_version{{version="{_get_current_version()}"}} 1',
        "",
        "# HELP unison_policy_reload_total Total number of bundle reload attempts",
        "# TYPE unison_policy_reload_total counter",
        f"unison_policy_reload_total {reload_stats['total_reloads']}",
        "",
        "# HELP unison_policy_reload_success_total Total number of successful bundle reloads",
        "# TYPE unison_policy_reload_success_total counter",
        f"unison_policy_reload_success_total {reload_stats['successful_reloads']}",
        "",
        "# HELP unison_policy_reload_failure_total Total number of failed bundle reloads",
        "# TYPE unison_policy_reload_failure_total counter",
        f"unison_policy_reload_failure_total {reload_stats['failed_reloads']}",
        "",
        "# HELP unison_policy_reload_success_rate Percentage of successful reloads",
        "# TYPE unison_policy_reload_success_rate gauge",
        f"unison_policy_reload_success_rate {reload_stats['success_rate']}",
        "",
        "# HELP unison_policy_reload_duration_seconds Average reload duration in seconds",
        "# TYPE unison_policy_reload_duration_seconds gauge",
        f"unison_policy_reload_duration_seconds {reload_stats['avg_duration_ms'] / 1000}",
    ])
    
    # Add bundle loaded timestamp if available
    loaded_at = _get_loaded_at()
    if loaded_at:
        lines.extend([
            "",
            "# HELP unison_policy_bundle_loaded_timestamp Unix timestamp when bundle was loaded",
            "# TYPE unison_policy_bundle_loaded_timestamp gauge",
            f"unison_policy_bundle_loaded_timestamp {int(datetime.fromisoformat(loaded_at).timestamp())}",
        ])
    
    return "\n".join(lines)

@app.get("/readyz")
@app.get("/ready")
def ready(request: Request):
    event_id = request.headers.get("X-Event-ID")
    
    # Check if bundle is loaded and not stale
    loaded_at = _get_loaded_at()
    bundle_age_hours = None
    is_stale = False
    
    if loaded_at:
        loaded_time = datetime.fromisoformat(loaded_at)
        age = datetime.now(timezone.utc) - loaded_time
        bundle_age_hours = age.total_seconds() / 3600
        is_stale = bundle_age_hours > 24  # Warn if bundle is > 24 hours old
    
    ready_status = {
        "ready": True,
        "bundle_version": _get_current_version(),
        "bundle_loaded_at": loaded_at,
        "bundle_age_hours": round(bundle_age_hours, 2) if bundle_age_hours else None,
        "bundle_stale": is_stale
    }
    
    log_json(
        logging.INFO, 
        "ready", 
        service="unison-policy", 
        event_id=event_id, 
        ready=True,
        bundle_version=_get_current_version()
    )
    
    return ready_status


@app.get("/rules/summary")
def rules_summary(request: Request):
    _metrics["/rules/summary"] += 1
    event_id = request.headers.get("X-Event-ID")
    summary = {"count": len(_get_current_rules()), "path": RULES_PATH}
    log_json(logging.INFO, "rules_summary", service="unison-policy", event_id=event_id, count=summary["count"]) 
    return summary

@app.get("/rules")
def list_rules(request: Request):
    _metrics["/rules"] += 1
    event_id = request.headers.get("X-Event-ID")
    log_json(logging.INFO, "rules_list", service="unison-policy", event_id=event_id, count=len(_get_current_rules()))
    return {
        "ok": True,
        "rules": _get_current_rules(),
        "count": len(_get_current_rules()),
        "policy_version": _get_current_version()
    }

@app.post("/rules")
def update_rules(request: Request, body: Dict[str, Any] = Body(...)):
    """
    Admin endpoint to replace the in-memory rule set at runtime.
    Expects {"rules": [...]} matching the YAML schema.
    """
    _metrics["/rules"] += 1
    event_id = request.headers.get("X-Event-ID")
    rules = body.get("rules")
    if not isinstance(rules, list):
        raise HTTPException(status_code=400, detail="Invalid or missing 'rules' list")
    # Basic validation: each rule must have 'match' and 'decision'
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise HTTPException(status_code=400, detail=f"Rule {i} is not an object")
        if "match" not in rule or "decision" not in rule:
            raise HTTPException(status_code=400, detail=f"Rule {i} missing 'match' or 'decision'")
    # Accept the new rule set
    _RULES_REF['value'] = rules
    log_json(logging.INFO, "rules_updated", service="unison-policy", event_id=event_id, count=len(rules))
    return {"ok": True, "rules": len(rules)}

@app.post("/evaluate")
def evaluate(
    request: Request,
    capability_id: str = Body(..., embed=True),
    context: dict = Body(default_factory=dict, embed=True),
):
    _metrics["/evaluate"] += 1
    event_id = request.headers.get("X-Event-ID")
    # Extract person_id if provided
    person_id = context.get("person_id", "unknown")
    # Evaluate rules if available
    decision = {
        "allowed": True,
        "require_confirmation": False,
        "reason": "default-allow",
        "suggested_alternative": None,
    }

    try:
        for rule in _get_current_rules():
            match = rule.get("match", {})
            dec = rule.get("decision", {})
            intent_prefix = match.get("intent_prefix")
            auth_scope = match.get("auth_scope")
            data_class = (match.get("safety_context") or {}).get("data_classification")
            time_window = match.get("time_window", {})
            persons = match.get("persons")

            ok = True
            if intent_prefix and not str(capability_id).startswith(str(intent_prefix)):
                ok = False
            if ok and auth_scope and str(context.get("auth_scope")) != str(auth_scope):
                ok = False
            if ok and data_class:
                sc = (context.get("safety_context") or {}).get("data_classification")
                if str(sc) != str(data_class):
                    ok = False
            if ok and time_window:
                start = time_window.get("start")
                end = time_window.get("end")
                if isinstance(start, str) and isinstance(end, str):
                    if not _time_in_window(start, end):
                        ok = False
                else:
                    ok = False
            if ok and persons:
                if not _matches_persons(persons, person_id):
                    ok = False
            if not ok:
                continue

            action = str(dec.get("action", "allow"))
            reason = dec.get("reason", f"rule:{intent_prefix or '*'}")
            suggested = dec.get("suggested_alternative")
            if action == "deny":
                decision = {"allowed": False, "require_confirmation": False, "reason": reason, "suggested_alternative": suggested}
            elif action == "require_confirmation":
                decision = {"allowed": False, "require_confirmation": True, "reason": reason, "suggested_alternative": suggested}
            else:
                decision = {"allowed": True, "require_confirmation": False, "reason": reason, "suggested_alternative": suggested}
            break
    except Exception as e:
        logger.exception("policy_eval_error: %s", e)

    log_json(
        logging.INFO,
        "policy_evaluate",
        service="unison-policy",
        event_id=event_id,
        capability_id=capability_id,
        person_id=person_id,
        decision=decision,
        rules=len(_get_current_rules()),
    )
    return {
        "capability_id": capability_id,
        "decision": decision,
        "policy_version": _get_current_version(),
    }

# --- Bundle Management Endpoints ---

@app.get("/bundle")
def get_current_bundle():
    """Get information about the currently loaded policy bundle"""
    bundle = _get_current_bundle()
    
    if bundle:
        metadata = bundle.get('metadata', {})
        return {
            "bundle_loaded": True,
            "bundle_id": metadata.get('bundle_id'),
            "version": metadata.get('version'),
            "issued_at": metadata.get('issued_at'),
            "issuer": metadata.get('issuer'),
            "loaded_at": _get_loaded_at(),
            "policies_count": len(bundle.get('policies', [])),
            "signature_verified": True
        }
    else:
        return {
            "bundle_loaded": False,
            "rules_count": len(_get_current_rules()),
            "source": "yaml_file"
        }

@app.post("/reload")
@app.post("/bundle/reload")
def reload_bundle_endpoint(bundle_path: str = Body(default=None, embed=True)):
    """
    Hot-reload policy bundle atomically
    
    If bundle_path is provided, loads that specific bundle.
    Otherwise, reloads from the default BUNDLE_PATH.
    """
    _metrics["/reload"] += 1
    
    path = bundle_path or BUNDLE_PATH
    
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Bundle file not found: {path}")
    
    # Perform hot-reload
    result = hot_reload_bundle(
        bundle_path=path,
        bundle_signer=_BUNDLE_SIGNER,
        load_bundle_func=load_bundle,
        load_policies_func=load_policies_from_bundle,
        current_bundle_ref=_BUNDLE_REF,
        current_rules_ref=_RULES_REF,
        current_version_ref=_VERSION_REF
    )
    
    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=500, detail=result["error"])

@app.post("/bundle/verify")
def verify_bundle_endpoint(bundle_path: str = Body(..., embed=True)):
    """Verify a signed policy bundle without loading it"""
    if not os.path.exists(bundle_path):
        raise HTTPException(status_code=404, detail=f"Bundle file not found: {bundle_path}")
    
    # Initialize bundle signer if needed
    global _BUNDLE_SIGNER
    if _BUNDLE_SIGNER is None:
        _BUNDLE_SIGNER = PolicyBundleSigner()
    
    # Load and verify bundle
    try:
        bundle = _BUNDLE_SIGNER.load_bundle(bundle_path)
        is_valid = _BUNDLE_SIGNER.verify_bundle(bundle)
        
        if is_valid:
            metadata = bundle.get('metadata', {})
            return {
                "valid": True,
                "bundle_id": metadata.get('bundle_id'),
                "version": metadata.get('version'),
                "issued_at": metadata.get('issued_at'),
                "issuer": metadata.get('issuer'),
                "policies_count": len(bundle.get('policies', []))
            }
        else:
            return {"valid": False, "error": "Signature verification failed"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bundle verification error: {str(e)}")

@app.get("/bundle/policies")
def get_bundle_policies():
    """Get all policies from the current bundle or rules"""
    bundle = _get_current_bundle()
    if bundle:
        return {
            "source": "signed_bundle",
            "bundle_id": bundle.get('metadata', {}).get('bundle_id'),
            "policies": bundle.get('policies', [])
        }
    else:
        return {
            "source": "yaml_rules",
            "rules": _get_current_rules()
        }

@app.get("/reload/history")
def get_reload_history_endpoint():
    """Get hot-reload history (last 10 reloads)"""
    return {
        "history": get_reload_history()
    }

@app.get("/reload/stats")
def get_reload_stats_endpoint():
    """Get hot-reload statistics"""
    return get_reload_stats()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8083)
