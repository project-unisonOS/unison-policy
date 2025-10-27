from fastapi import FastAPI, Request
from fastapi import Body
import uvicorn
import logging
import json
import time
import os
from typing import Any, Dict, List
import yaml

app = FastAPI(title="unison-policy")

logger = logging.getLogger("unison-policy")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

def log_json(level: int, message: str, **fields):
    record = {"ts": time.time(), "service": "unison-policy", "message": message}
    record.update(fields)
    logger.log(level, json.dumps(record, separators=(",", ":")))

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

@app.get("/health")
def health(request: Request):
    event_id = request.headers.get("X-Event-ID")
    log_json(logging.INFO, "health", event_id=event_id)
    return {"status": "ok", "service": "unison-policy"}

@app.get("/ready")
def ready(request: Request):
    event_id = request.headers.get("X-Event-ID")
    # Future: check audit log backend / key store
    log_json(logging.INFO, "ready", event_id=event_id, ready=True)
    return {"ready": True}


@app.get("/rules/summary")
def rules_summary(request: Request):
    event_id = request.headers.get("X-Event-ID")
    summary = {"count": len(_RULES), "path": RULES_PATH}
    log_json(logging.INFO, "rules_summary", event_id=event_id, count=summary["count"]) 
    return summary

# Placeholder evaluate endpoint
# In the future orchestrator will call this before executing any high-risk capability.
@app.post("/evaluate")
def evaluate(
    request: Request,
    capability_id: str = Body(..., embed=True),
    context: dict = Body(default_factory=dict, embed=True),
):
    event_id = request.headers.get("X-Event-ID")
    # Evaluate rules if available
    decision = {
        "allowed": True,
        "require_confirmation": False,
        "reason": "default-allow",
    }

    try:
        for rule in _RULES:
            match = rule.get("match", {})
            dec = rule.get("decision", {})
            intent_prefix = match.get("intent_prefix")
            auth_scope = match.get("auth_scope")
            data_class = (match.get("safety_context") or {}).get("data_classification")

            ok = True
            if intent_prefix and not str(capability_id).startswith(str(intent_prefix)):
                ok = False
            if ok and auth_scope and str(context.get("auth_scope")) != str(auth_scope):
                ok = False
            if ok and data_class:
                sc = (context.get("safety_context") or {}).get("data_classification")
                if str(sc) != str(data_class):
                    ok = False
            if not ok:
                continue

            action = str(dec.get("action", "allow"))
            reason = dec.get("reason", f"rule:{intent_prefix or '*'}")
            if action == "deny":
                decision = {"allowed": False, "require_confirmation": False, "reason": reason}
            elif action == "require_confirmation":
                decision = {"allowed": False, "require_confirmation": True, "reason": reason}
            else:
                decision = {"allowed": True, "require_confirmation": False, "reason": reason}
            break
    except Exception as e:
        logger.exception("policy_eval_error: %s", e)

    log_json(
        logging.INFO,
        "policy_evaluate",
        event_id=event_id,
        capability_id=capability_id,
        decision=decision,
        rules=len(_RULES),
    )
    return {
        "capability_id": capability_id,
        "decision": decision,
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8083)
