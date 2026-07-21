from dataclasses import asdict

from trust_service import TrustEvaluator, TrustRepository, request_hash


BASE = {"principal_id": "p1", "assistant_id": "a1", "purpose": "assist", "audience": ["self"], "space_id": "private:p1", "assurance": "local-unlocked", "data_classes": ["personal"], "action": "read", "requested_fields": ["title", "time", "private_note", "location"]}


def test_unknown_dimensions_fail_closed():
    decision = TrustEvaluator(TrustRepository()).evaluate({**BASE, "purpose": "invented"})
    assert decision.outcome.value == "deny"
    assert decision.reason_code == "unknown-authority"


def test_minimum_context_is_enforced():
    decision = TrustEvaluator(TrustRepository()).evaluate(BASE)
    assert decision.outcome.value == "minimize"
    assert len(decision.disclosed_fields) == 3
    assert decision.redacted_fields == ("location",)


def test_prompt_injection_cannot_gain_authority():
    decision = TrustEvaluator(TrustRepository()).evaluate({**BASE, "action": "send", "untrusted_input": True})
    assert decision.outcome.value == "deny"
    assert decision.reason_code == "untrusted-instruction"


def test_confirmation_is_single_use_and_cancellable():
    repo = TrustRepository()
    evaluator = TrustEvaluator(repo)
    raw = {**BASE, "action": "send", "audience": ["work"], "recipient_ids": ["r1"]}
    decision = evaluator.evaluate(raw)
    from unison_common.trust_governance import TrustRequest
    req = TrustRequest.from_mapping(raw)
    assert repo.resolve_confirmation(decision.confirmation_id, "p1", request_hash(req), False) == "cancelled"
    assert repo.resolve_confirmation(decision.confirmation_id, "p1", request_hash(req), True) == "replayed"


def test_credential_broker_never_returns_plaintext_to_planner():
    repo = TrustRepository()
    cid = repo.store_credential("p1", "mail", "super-secret")
    assert repo.inject_credential(cid, "p1", "mail", lambda secret: {"authorization": secret}) == {"authorization": "super-secret"}
    assert "super-secret" not in str(repo.audit_for("p1"))


def test_capability_requires_grant_and_grant_is_intersection_not_ambient_authority():
    repo = TrustRepository(); evaluator = TrustEvaluator(repo)
    raw = {**BASE, "capability_id": "mail", "action": "draft"}
    assert evaluator.evaluate(raw).reason_code == "grant-required"
    from unison_common.trust_governance import CapabilityGrant
    repo.put_grant(CapabilityGrant.from_mapping({"grant_id": "g1", "principal_id": "p1", "assistant_id": "a1", "capability_id": "mail", "actions": ["draft"], "purposes": ["assist"], "audiences": ["self"], "data_classes": ["personal"], "space_ids": ["private:p1"], "max_risk": "low", "max_cost": "0"}))
    assert evaluator.evaluate(raw, grant_id="g1").outcome.value == "minimize"
    assert evaluator.evaluate({**raw, "risk_level": "high"}, grant_id="g1").reason_code == "grant-boundary"
