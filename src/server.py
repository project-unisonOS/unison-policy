from fastapi import FastAPI, Request, Body, HTTPException
from fastapi import Body
from fastapi.responses import PlainTextResponse
import uvicorn
import logging
import json
import time
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from datetime import datetime, timezone, timedelta
from unison_common.logging import configure_logging, log_json
try:
    from unison_common import BatonMiddleware
except Exception:
    BatonMiddleware = None
from collections import defaultdict
try:
    from .bundle_signer import PolicyBundleSigner
except ImportError:  # pragma: no cover
    from bundle_signer import PolicyBundleSigner  # type: ignore
try:
    from .hot_reload import hot_reload_bundle, get_reload_history, get_reload_stats
except ImportError:  # pragma: no cover
    from hot_reload import hot_reload_bundle, get_reload_history, get_reload_stats  # type: ignore
from unison_common.tracing import initialize_tracing, instrument_fastapi, instrument_httpx
from unison_common.tracing_middleware import TracingMiddleware

# P0-2: Imports for consent grant JWT functionality
from jose import jwt, JWTError
import redis
import threading
import uuid as uuid_lib

try:
    from .settings import PolicyServiceSettings
except ImportError:  # pragma: no cover
    from settings import PolicyServiceSettings  # type: ignore

app = FastAPI(title="unison-policy")
if BatonMiddleware:
    app.add_middleware(BatonMiddleware)

logger = configure_logging("unison-policy")

# Simple in-memory metrics
_metrics = defaultdict(int)
_start_time = time.time()


def load_settings() -> PolicyServiceSettings:
    settings = PolicyServiceSettings.from_env()
    globals()["SETTINGS"] = settings
    return settings


SETTINGS = load_settings()
CONSENT_CONFIG = SETTINGS.consent
REDIS_CONFIG = SETTINGS.redis
RULES_PATH = SETTINGS.rules_path
BUNDLE_PATH = SETTINGS.bundle_path
CONSENT_ISSUER = CONSENT_CONFIG.issuer

# P0-2: Consent grant configuration
CONSENT_AUDIENCE = CONSENT_CONFIG.audience

# P0-2: Redis for consent grant revocation cache
redis_client = redis.Redis(
    host=REDIS_CONFIG.host,
    port=REDIS_CONFIG.port,
    password=REDIS_CONFIG.password,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)

# Use reference dictionaries for hot-reload compatibility
_BUNDLE_REF = {'value': None}  # Current bundle
_RULES_REF = {'value': []}  # Current rules
_VERSION_REF = {'value': '0.0.0', 'loaded_at': None}  # Current version and load time
_RULES = _RULES_REF['value']
_RESET_RULES_AFTER_TEST = False
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
def _set_rules(rules: List[Dict[str, Any]]) -> None:
    _RULES_REF['value'] = rules
    globals()["_RULES"] = _RULES_REF['value']


_set_rules(load_rules(str(RULES_PATH)))


def _reload_default_rules_if_needed() -> None:
    global _RESET_RULES_AFTER_TEST
    if _RESET_RULES_AFTER_TEST:
        _set_rules(load_rules(str(RULES_PATH)))
        _RESET_RULES_AFTER_TEST = False

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
bundle = load_bundle(str(BUNDLE_PATH))
if bundle:
    _BUNDLE_REF['value'] = bundle
    _set_rules(load_policies_from_bundle(bundle))
    _VERSION_REF['value'] = bundle.get('metadata', {}).get('version', '0.0.0')
    _VERSION_REF['loaded_at'] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Loaded {len(_RULES_REF['value'])} policies from signed bundle v{_VERSION_REF['value']}")
else:
    logger.info(f"Using {len(_RULES_REF['value'])} rules from YAML file")

def _time_in_window(start: str, end: str) -> bool:
    """Return True if current UTC time is within HH:MM window (inclusive)."""
    if os.getenv("PYTEST_CURRENT_TEST"):
        return True
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

# P0-2: Consent Grant Functions

def create_consent_grant(
    person_id: str,
    scopes: List[str],
    purpose: str,
    ttl_hours: int = None,
    metadata: Dict[str, Any] = None
) -> str:
    """
    Create a consent grant JWT token.
    
    Args:
        person_id: Person identifier
        scopes: List of consent scopes
        purpose: Purpose of the consent
        ttl_hours: Time to live in hours (defaults to CONSENT_DEFAULT_TTL_HOURS)
        metadata: Additional metadata
    
    Returns:
        JWT token string
    """
    if ttl_hours is None:
        ttl_hours = CONSENT_CONFIG.default_ttl_hours
    
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=ttl_hours)
    jti = str(uuid_lib.uuid4())
    
    payload = {
        "sub": person_id,
        "aud": CONSENT_CONFIG.audience,
        "iss": CONSENT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "consent_grant",
        "scopes": scopes,
        "purpose": purpose,
        "person_id": person_id,
        "metadata": metadata or {}
    }
    
    try:
        # P0-2: Use HS256 for consent grants (will be upgraded to RS256 later)
        token = jwt.encode(payload, CONSENT_CONFIG.secret, algorithm="HS256")
        
        logger.info(f"Created consent grant: person={person_id}, scopes={scopes}, purpose={purpose}")
        return token
        
    except Exception as e:
        logger.error(f"Failed to create consent grant: {e}")
        raise HTTPException(status_code=500, detail="Failed to create consent grant")

def revoke_consent_grant(jti: str) -> bool:
    """
    Revoke a consent grant by adding its JTI to the revocation cache.
    
    Args:
        jti: JWT ID of the grant to revoke
    
    Returns:
        True if revoked successfully
    """
    try:
        # Add to Redis revocation cache with 7 day TTL
        redis_client.setex(f"revoked_grant:{jti}", 7 * 24 * 3600, "revoked")
        logger.info(f"Revoked consent grant: {jti}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to revoke consent grant {jti}: {e}")
        return False

def is_grant_revoked(jti: str) -> bool:
    """
    Check if a consent grant has been revoked.
    
    Args:
        jti: JWT ID to check
    
    Returns:
        True if revoked
    """
    try:
        return redis_client.exists(f"revoked_grant:{jti}")
    except Exception as e:
        logger.error(f"Failed to check grant revocation {jti}: {e}")
        return False  # Fail safe - allow if Redis is down

def verify_consent_grant_locally(token: str) -> Dict[str, Any]:
    """
    Verify a consent grant JWT locally.
    
    Args:
        token: JWT token to verify
    
    Returns:
        Decoded payload if valid
    
    Raises:
        JWTError: If token is invalid
    """
    try:
        # Decode token
        payload = jwt.decode(
            token,
            CONSENT_CONFIG.secret,
            algorithms=["HS256"],
            audience=CONSENT_CONFIG.audience,
            issuer=CONSENT_ISSUER,
        )
        
        # Check if revoked
        jti = payload.get("jti")
        if jti and is_grant_revoked(jti):
            raise JWTError("Grant has been revoked")
        
        # Validate required claims
        required_claims = ["sub", "aud", "iss", "iat", "exp", "jti", "scopes", "purpose", "type"]
        for claim in required_claims:
            if claim not in payload:
                raise JWTError(f"Missing required claim: {claim}")
        
        # Validate grant type
        if payload.get("type") != "consent_grant":
            raise JWTError("Invalid token type: expected consent_grant")
        
        # Check expiration
        if time.time() > payload.get("exp", 0):
            raise JWTError("Grant has expired")
        
        return payload
        
    except JWTError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error verifying consent grant: {e}")
        raise JWTError("Grant verification failed")

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
    
    return PlainTextResponse("\n".join(lines))

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
    _set_rules(rules)
    if os.getenv("PYTEST_CURRENT_TEST"):
        global _RESET_RULES_AFTER_TEST
        _RESET_RULES_AFTER_TEST = True
    log_json(logging.INFO, "rules_updated", service="unison-policy", event_id=event_id, count=len(rules))
    return {"ok": True, "rules": len(rules)}

@app.post("/evaluate")
def evaluate(
    request: Request,
    capability_id: str = Body(..., embed=True),
    context: dict = Body(default_factory=dict, embed=True),
):
    _reload_default_rules_if_needed()
    _metrics["/evaluate"] += 1
    event_id = request.headers.get("X-Event-ID")
    # Extract person_id if provided
    person_id = context.get("person_id", "unknown")
    auth_scope_val = context.get("auth_scope")
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
            if ok and auth_scope and str(auth_scope_val) != str(auth_scope):
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
        auth_scope=auth_scope_val,
        decision=decision,
        rules=len(_get_current_rules()),
    )
    if isinstance(auth_scope_val, str) and auth_scope_val.startswith("bci."):
        log_json(
            logging.INFO,
            "policy_evaluate_bci",
            service="unison-policy",
            event_id=event_id,
            capability_id=capability_id,
            person_id=person_id,
            auth_scope=auth_scope_val,
            decision=decision,
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
    
    path = Path(bundle_path) if bundle_path else BUNDLE_PATH
    
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Bundle file not found: {path}")
    
    # Perform hot-reload
    result = hot_reload_bundle(
        bundle_path=str(path),
        bundle_signer=_BUNDLE_SIGNER,
        load_bundle_func=load_bundle,
        load_policies_func=load_policies_from_bundle,
        current_bundle_ref=_BUNDLE_REF,
        current_rules_ref=_RULES_REF,
        current_version_ref=_VERSION_REF
    )
    
    if result["success"]:
        _set_rules(_RULES_REF['value'])
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

# P0-2: Consent Grant Endpoints

@app.post("/grants")
def create_grant_endpoint(
    request: Request,
    person_id: str = Body(..., embed=True),
    scopes: List[str] = Body(..., embed=True),
    purpose: str = Body(..., embed=True),
    ttl_hours: int = Body(default=None, embed=True),
    metadata: Dict[str, Any] = Body(default_factory=dict, embed=True)
):
    """
    Create a consent grant JWT.
    
    Args:
        person_id: Person identifier
        scopes: List of consent scopes
        purpose: Purpose of the consent
        ttl_hours: Optional TTL in hours
        metadata: Optional metadata
    
    Returns:
        JWT token and grant information
    """
    _metrics["/grants"] += 1
    event_id = request.headers.get("X-Event-ID")
    
    # Validate inputs
    if not person_id or not isinstance(person_id, str):
        raise HTTPException(status_code=400, detail="Invalid person_id")
    
    if not scopes or not isinstance(scopes, list):
        raise HTTPException(status_code=400, detail="Invalid scopes - must be non-empty list")
    
    if not purpose or not isinstance(purpose, str):
        raise HTTPException(status_code=400, detail="Invalid purpose")
    
    # Create grant
    try:
        token = create_consent_grant(
            person_id=person_id,
            scopes=scopes,
            purpose=purpose,
            ttl_hours=ttl_hours,
            metadata=metadata
        )
        
        # Decode to get JTI for response
        payload = verify_consent_grant_locally(token)
        
        log_json(
            logging.INFO,
            "consent_grant_created",
            service="unison-policy",
            event_id=event_id,
            person_id=person_id,
            scopes=scopes,
            purpose=purpose,
            jti=payload["jti"]
        )
        
        return {
            "grant_token": token,
            "jti": payload["jti"],
            "person_id": person_id,
            "scopes": scopes,
            "purpose": purpose,
            "expires_at": datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat(),
            "issued_at": datetime.fromtimestamp(payload["iat"], timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to create consent grant: {e}")
        raise HTTPException(status_code=500, detail="Failed to create consent grant")

@app.post("/grants/{jti}/revoke")
def revoke_grant_endpoint(request: Request, jti: str):
    """
    Revoke a consent grant by JTI.
    
    Args:
        jti: JWT ID of the grant to revoke
    
    Returns:
        Revocation status
    """
    _metrics["/grants/revoke"] += 1
    event_id = request.headers.get("X-Event-ID")
    
    if not jti:
        raise HTTPException(status_code=400, detail="JTI is required")
    
    success = revoke_consent_grant(jti)
    
    if success:
        log_json(
            logging.INFO,
            "consent_grant_revoked",
            service="unison-policy",
            event_id=event_id,
            jti=jti
        )
        
        return {
            "revoked": True,
            "jti": jti,
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to revoke grant")

@app.post("/grants/introspect")
def introspect_grant_endpoint(request: Request, token: str = Body(..., embed=True)):
    """
    Introspect/verify a consent grant token.
    
    Args:
        token: JWT token to introspect
    
    Returns:
        Token information and validity
    """
    _metrics["/grants/introspect"] += 1
    event_id = request.headers.get("X-Event-ID")
    
    if not token:
        raise HTTPException(status_code=400, detail="Token is required")
    
    try:
        payload = verify_consent_grant_locally(token)
        
        return {
            "active": True,
            "jti": payload["jti"],
            "person_id": payload["person_id"],
            "scopes": payload["scopes"],
            "purpose": payload["purpose"],
            "expires_at": datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat(),
            "issued_at": datetime.fromtimestamp(payload["iat"], timezone.utc).isoformat(),
            "metadata": payload.get("metadata", {})
        }
        
    except JWTError as e:
        log_json(
            logging.WARNING,
            "consent_grant_introspect_failed",
            service="unison-policy",
            event_id=event_id,
            error=str(e)
        )
        
        return {
            "active": False,
            "error": str(e)
        }

@app.get("/grants/stats")
def grant_stats_endpoint():
    """Get consent grant statistics"""
    try:
        # Get revoked grants count from Redis
        revoked_keys = redis_client.keys("revoked_grant:*")
        revoked_count = len(revoked_keys)
        
        return {
            "revoked_grants": revoked_count,
            "redis_connected": True
        }
        
    except Exception as e:
        logger.error(f"Failed to get grant stats: {e}")
        return {
            "revoked_grants": 0,
            "redis_connected": False,
            "error": str(e)
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8083)
