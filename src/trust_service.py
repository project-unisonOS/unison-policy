"""Authoritative Phase 3 policy, disclosure, confirmation, and credential boundary."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Iterable
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Body, HTTPException
from unison_common.trust_governance import (
    AssuranceLevel,
    CapabilityGrant,
    DecisionOutcome,
    DisclosureDecision,
    RiskLevel,
    TrustRequest,
)


VOCABULARY = {
    "purposes": {"assist", "communicate", "schedule", "purchase", "health-support", "work", "household"},
    "audiences": {"self", "household", "family", "friend", "work", "service-provider"},
    "data_classes": {"public", "personal", "relationship", "location", "financial", "health", "credential"},
    "assurance": {item.value for item in AssuranceLevel},
    "channels": {"local", "web", "sms", "voice", "whatsapp", "telegram", "email", "api"},
}
SENSITIVE = {"financial", "health", "credential", "location"}
EXTERNAL_AUDIENCES = {"family", "friend", "work", "service-provider"}
HIGH_RISK_ACTIONS = {"send", "publish", "purchase", "transfer", "delete", "unlock", "execute"}
STRONG_ASSURANCE = {AssuranceLevel.STRONG.value, AssuranceLevel.HARDWARE.value}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TrustRepository:
    """Durable local evidence store. Secret plaintext never enters decision/audit rows."""

    def __init__(self, path: str | Path = ":memory:", *, key: bytes | None = None):
        self.path = str(path)
        self._lock = RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._fernet = Fernet(key or Fernet.generate_key())
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, body TEXT NOT NULL, revoked_at TEXT);
        CREATE TABLE IF NOT EXISTS confirmations(id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, request_hash TEXT NOT NULL, expires_at TEXT NOT NULL, state TEXT NOT NULL, consumed_at TEXT);
        CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, capability_id TEXT NOT NULL, ciphertext BLOB NOT NULL, revoked_at TEXT);
        CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, action TEXT NOT NULL, explanation TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        """)
        self._db.execute("INSERT OR IGNORE INTO migrations VALUES(3, ?)", (_utcnow().isoformat(),))
        self._db.commit()

    def record_decision(self, principal_id: str, decision: DisclosureDecision) -> None:
        body = decision.to_dict()
        with self._lock:
            self._db.execute("INSERT INTO decisions VALUES(?,?,?,?)", (decision.request_id, principal_id, json.dumps(body, sort_keys=True), decision.created_at))
            self._db.execute("INSERT INTO audit VALUES(?,?,?,?,?,?)", (str(uuid4()), principal_id, "trust-decision", decision.explanation, json.dumps({"outcome": decision.outcome.value, "reason_code": decision.reason_code, "consequence": decision.consequence}), decision.created_at))
            self._db.commit()

    def put_grant(self, grant: CapabilityGrant) -> None:
        body = asdict(grant)
        body["max_risk"] = grant.max_risk.value
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO grants VALUES(?,?,?,?)", (grant.grant_id, grant.principal_id, json.dumps(body, sort_keys=True), grant.revoked_at))
            self._db.commit()

    def get_grant(self, grant_id: str) -> CapabilityGrant | None:
        row = self._db.execute("SELECT body,revoked_at FROM grants WHERE id=?", (grant_id,)).fetchone()
        if not row or row["revoked_at"]:
            return None
        return CapabilityGrant.from_mapping(json.loads(row["body"]))

    def revoke_grant(self, grant_id: str) -> bool:
        now = _utcnow().isoformat()
        with self._lock:
            cur = self._db.execute("UPDATE grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, grant_id))
            self._db.commit()
        return cur.rowcount == 1

    def create_confirmation(self, principal_id: str, request_hash: str, ttl_seconds: int = 300) -> tuple[str, str]:
        confirmation_id, expires = str(uuid4()), (_utcnow() + timedelta(seconds=min(max(ttl_seconds, 1), 600))).isoformat()
        with self._lock:
            self._db.execute("INSERT INTO confirmations VALUES(?,?,?,?,?,NULL)", (confirmation_id, principal_id, request_hash, expires, "pending"))
            self._db.commit()
        return confirmation_id, expires

    def resolve_confirmation(self, confirmation_id: str, principal_id: str, request_hash: str, approve: bool) -> str:
        with self._lock:
            row = self._db.execute("SELECT * FROM confirmations WHERE id=?", (confirmation_id,)).fetchone()
            if not row or row["principal_id"] != principal_id or row["request_hash"] != request_hash:
                return "invalid"
            if row["state"] != "pending":
                return "replayed"
            if datetime.fromisoformat(row["expires_at"]) <= _utcnow():
                self._db.execute("UPDATE confirmations SET state='expired' WHERE id=?", (confirmation_id,))
                self._db.commit()
                return "expired"
            state = "approved" if approve else "cancelled"
            self._db.execute("UPDATE confirmations SET state=?,consumed_at=? WHERE id=?", (state, _utcnow().isoformat(), confirmation_id))
            self._db.commit()
            return state

    def store_credential(self, principal_id: str, capability_id: str, value: str) -> str:
        credential_id = str(uuid4())
        ciphertext = self._fernet.encrypt(value.encode("utf-8"))
        with self._lock:
            self._db.execute("INSERT INTO credentials VALUES(?,?,?,?,NULL)", (credential_id, principal_id, capability_id, ciphertext))
            self._db.commit()
        return credential_id

    def inject_credential(self, credential_id: str, principal_id: str, capability_id: str, consumer) -> Any:
        row = self._db.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row or row["revoked_at"] or row["principal_id"] != principal_id or row["capability_id"] != capability_id:
            raise PermissionError("credential is unavailable for this task")
        try:
            secret = self._fernet.decrypt(row["ciphertext"]).decode("utf-8")
        except InvalidToken as exc:
            raise PermissionError("credential cannot be decrypted") from exc
        return consumer(secret)

    def audit_for(self, principal_id: str) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT action,explanation,body,created_at FROM audit WHERE principal_id=? ORDER BY created_at", (principal_id,)).fetchall()
        return [{**json.loads(row["body"]), "action": row["action"], "explanation": row["explanation"], "created_at": row["created_at"]} for row in rows]


def request_hash(request: TrustRequest) -> str:
    return hashlib.sha256(json.dumps(asdict(request), sort_keys=True).encode()).hexdigest()


class TrustEvaluator:
    def __init__(self, repository: TrustRepository):
        self.repository = repository

    def evaluate(self, raw: dict[str, Any], *, grant_id: str | None = None) -> DisclosureDecision:
        try:
            request = TrustRequest.from_mapping(raw)
        except (TypeError, ValueError) as exc:
            return DisclosureDecision(DecisionOutcome.DENY, "incomplete-authority", f"I did not act because authority was incomplete: {exc}")

        unknown = self._unknown_dimensions(request)
        if unknown:
            decision = DisclosureDecision(DecisionOutcome.DENY, "unknown-authority", "I did not act because these authority values are unknown: " + ", ".join(unknown))
        elif request.untrusted_input and request.action in HIGH_RISK_ACTIONS:
            decision = DisclosureDecision(DecisionOutcome.DENY, "untrusted-instruction", "I treated embedded instructions as untrusted content and did not give them authority.")
        elif grant_id and not self._grant_allows(self.repository.get_grant(grant_id), request):
            decision = DisclosureDecision(DecisionOutcome.DENY, "grant-boundary", "I did not act because the capability grant does not cover this request.")
        elif request.action in HIGH_RISK_ACTIONS and request.assurance not in STRONG_ASSURANCE and SENSITIVE.intersection(request.data_classes):
            decision = DisclosureDecision(DecisionOutcome.STEP_UP, "strong-auth-required", "Please verify with a strong authentication method before I continue.", required_assurance="strong", alternatives=("Cancel", "Use a local-only alternative"))
        elif request.action in HIGH_RISK_ACTIONS or EXTERNAL_AUDIENCES.intersection(request.audience):
            cid, expiry = self.repository.create_confirmation(request.principal_id, request_hash(request))
            decision = DisclosureDecision(DecisionOutcome.ASK, "confirmation-required", "Please confirm the action, recipients, information, cost, and consequences before I continue.", confirmation_id=cid, expires_at=expiry, consequence="This may disclose information or change an external system.", alternatives=("Cancel", "Edit recipients", "Use less information"))
        elif "credential" in request.data_classes:
            decision = DisclosureDecision(DecisionOutcome.REDACT, "credential-redaction", "I removed credentials before preparing this request.", redacted_fields=request.requested_fields or ("credentials",))
        elif request.requested_fields:
            disclosed = tuple(request.requested_fields[: min(3, len(request.requested_fields))])
            redacted = tuple(field for field in request.requested_fields if field not in disclosed)
            decision = DisclosureDecision(DecisionOutcome.MINIMIZE, "minimum-context", "I will use only the fields needed for this purpose.", disclosed_fields=disclosed, redacted_fields=redacted)
        else:
            decision = DisclosureDecision(DecisionOutcome.ALLOW, "bounded-authority", "This request stays within the person-approved purpose and context boundary.")
        self.repository.record_decision(request.principal_id if 'request' in locals() else str(raw.get("principal_id", "unknown")), decision)
        return decision

    @staticmethod
    def _unknown_dimensions(request: TrustRequest) -> list[str]:
        unknown: list[str] = []
        if request.purpose not in VOCABULARY["purposes"]: unknown.append("purpose=" + request.purpose)
        unknown += ["audience=" + v for v in request.audience if v not in VOCABULARY["audiences"]]
        unknown += ["data_class=" + v for v in request.data_classes if v not in VOCABULARY["data_classes"]]
        if request.assurance not in VOCABULARY["assurance"]: unknown.append("assurance=" + request.assurance)
        if request.channel not in VOCABULARY["channels"]: unknown.append("channel=" + request.channel)
        return unknown

    @staticmethod
    def _grant_allows(grant: CapabilityGrant | None, request: TrustRequest) -> bool:
        if not grant or grant.principal_id != request.principal_id or grant.assistant_id != request.assistant_id:
            return False
        if request.capability_id != grant.capability_id or request.action not in grant.actions or request.purpose not in grant.purposes:
            return False
        return set(request.audience) <= set(grant.audiences) and set(request.data_classes) <= set(grant.data_classes) and request.space_id in grant.space_ids and set(request.recipient_ids) <= set(grant.recipient_ids)


DB_PATH = os.getenv("UNISON_TRUST_DB", ":memory:")
KEY = os.getenv("UNISON_CREDENTIAL_KEY")
repository = TrustRepository(DB_PATH, key=KEY.encode() if KEY else None)
evaluator = TrustEvaluator(repository)
router = APIRouter(prefix="/v1/trust", tags=["trust"])


@router.post("/evaluate")
def evaluate_trust(body: dict[str, Any] = Body(...)):
    return evaluator.evaluate(body.get("request", body), grant_id=body.get("grant_id")).to_dict()


@router.post("/grants", status_code=201)
def create_grant(body: dict[str, Any] = Body(...)):
    try:
        grant = CapabilityGrant.from_mapping(body)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    repository.put_grant(grant)
    return {"grant_id": grant.grant_id, "status": "active", "contract_version": grant.contract_version}


@router.delete("/grants/{grant_id}")
def revoke_grant(grant_id: str):
    if not repository.revoke_grant(grant_id):
        raise HTTPException(status_code=404, detail="active grant not found")
    return {"grant_id": grant_id, "status": "revoked"}


@router.post("/confirmations/{confirmation_id}")
def confirm(confirmation_id: str, body: dict[str, Any] = Body(...)):
    try:
        request = TrustRequest.from_mapping(body["request"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    state = repository.resolve_confirmation(confirmation_id, request.principal_id, request_hash(request), bool(body.get("approve")))
    if state in {"invalid", "replayed", "expired"}:
        raise HTTPException(status_code=409, detail=state)
    return {"confirmation_id": confirmation_id, "state": state, "reversible": False}


@router.get("/audit/{principal_id}")
def audit(principal_id: str):
    return {"principal_id": principal_id, "events": repository.audit_for(principal_id)}


@router.post("/credentials", status_code=201)
def store_credential(body: dict[str, Any] = Body(...)):
    required = ("principal_id", "capability_id", "secret")
    if any(not body.get(key) for key in required):
        raise HTTPException(status_code=422, detail="principal_id, capability_id, and secret are required")
    cid = repository.store_credential(body["principal_id"], body["capability_id"], body["secret"])
    return {"credential_id": cid, "status": "stored", "secret": "[REDACTED]"}
