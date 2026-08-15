from datetime import timedelta
from cryptography.hazmat.primitives import serialization
from unison_common.governed_context import utc_now
from unison_common.governed_memory import TaxonomySecurityReview
from taxonomy_policy import TaxonomyPolicyIssuer

def test_policy_issuer_produces_verifiable_person_bound_authorization(tmp_path):
    issuer = TaxonomyPolicyIssuer(tmp_path / "policy.pem")
    review = TaxonomySecurityReview(review_id="r1", proposal_id="p1", decision="approve",
        policy_version="v1", separate_key_boundary=True, retention_reviewed=True,
        sharing_reviewed=True, disclosure_reviewed=True, rationale="complete")
    issuance = issuer.issue(owner_person_id="alice", review=review)
    public = serialization.load_pem_public_key(issuer.public_key_pem())
    assert issuance.verify(public, owner_person_id="alice", proposal_id="p1") == review
