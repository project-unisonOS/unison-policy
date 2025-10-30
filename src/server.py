from fastapi import FastAPI, Request, Body, HTTPException
from fastapi import Body
import uvicorn
import logging
import json
import time
import os
from typing import Any, Dict, List
import yaml
from datetime import datetime, timezone
from unison_common.logging import configure_logging, log_json
from collections import defaultdict

app = FastAPI(title="unison-policy")

logger = configure_logging("unison-policy")

# Simple in-memory metrics
_metrics = defaultdict(int)
_start_time = time.time()

RULES_PATH = os.getenv("UNISON_POLICY_RULES", "rules.yaml")
_RULES: List[Dict[str, Any]] = []

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

_RULES = load_rules(RULES_PATH)

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
        f"unison_policy_rules_loaded {len(_RULES)}",
    ])
    return "\n".join(lines)

@app.get("/ready")
def ready(request: Request):
    event_id = request.headers.get("X-Event-ID")
    # Future: check audit log backend / key store
    log_json(logging.INFO, "ready", service="unison-policy", event_id=event_id, ready=True)
    return {"ready": True}


@app.get("/rules/summary")
def rules_summary(request: Request):
    _metrics["/rules/summary"] += 1
    event_id = request.headers.get("X-Event-ID")
    summary = {"count": len(_RULES), "path": RULES_PATH}
    log_json(logging.INFO, "rules_summary", service="unison-policy", event_id=event_id, count=summary["count"]) 
    return summary

@app.get("/rules")
def list_rules(request: Request):
    _metrics["/rules"] += 1
    event_id = request.headers.get("X-Event-ID")
    log_json(logging.INFO, "rules_list", service="unison-policy", event_id=event_id, count=len(_RULES))
    return {"ok": True, "rules": _RULES, "count": len(_RULES)}

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
    global _RULES
    _RULES = rules
    log_json(logging.INFO, "rules_updated", service="unison-policy", event_id=event_id, count=len(_RULES))
    return {"ok": True, "rules": len(_RULES)}

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
        for rule in _RULES:
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
        rules=len(_RULES),
    )
    return {
        "capability_id": capability_id,
        "decision": decision,
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8083)
