"""Signed policy issuance for person-owned taxonomy security boundaries."""
from __future__ import annotations
from datetime import timedelta
from pathlib import Path
from uuid import uuid4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from unison_common.governed_context import utc_now
from unison_common.governed_memory import SignedTaxonomyPolicyIssuance, TaxonomySecurityReview

class TaxonomyPolicyIssuer:
    def __init__(self, key_path: Path, *, key_id: str = "taxonomy-policy-1"):
        self.key_path, self.key_id = key_path, key_id
        self._key = self._load_or_create()
    def _load_or_create(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("taxonomy policy key must be Ed25519")
            return key
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return key
    def issue(self, *, owner_person_id: str, review: TaxonomySecurityReview,
              ttl_seconds: int = 300) -> SignedTaxonomyPolicyIssuance:
        if review.decision != "approve":
            raise ValueError("only approved security reviews can authorize activation")
        now = utc_now()
        issuance = SignedTaxonomyPolicyIssuance(issuance_id=str(uuid4()), owner_person_id=owner_person_id,
            proposal_id=review.proposal_id, review=review, issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds), key_id=self.key_id)
        return issuance.sign(self._key)
    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
