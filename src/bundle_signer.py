#!/usr/bin/env python3
"""
Policy Bundle Signer for Unison Platform

Creates signed policy bundles that can be distributed to policy services.
Bundles contain policies, metadata, and cryptographic signatures.
"""

import os
import json
import yaml
import time
import hashlib
import argparse
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

class PolicyBundleSigner:
    """Signs and validates policy bundles"""
    
    def __init__(self, private_key_path: str = None, public_key_path: str = None):
        """
        Initialize the signer with key paths
        
        Args:
            private_key_path: Path to PEM-encoded private key
            public_key_path: Path to PEM-encoded public key
        """
        self.private_key_path = private_key_path or "keys/private_key.pem"
        self.public_key_path = public_key_path or "keys/public_key.pem"
        self.private_key = None
        self.public_key = None
        
        self._load_keys()
    
    def _load_keys(self):
        """Load RSA keys from files or generate new ones"""
        # Create keys directory if it doesn't exist
        os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
        
        # Load or generate private key
        if os.path.exists(self.private_key_path):
            with open(self.private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self._save_private_key()
        
        # Load or generate public key
        if os.path.exists(self.public_key_path):
            with open(self.public_key_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        else:
            self.public_key = self.private_key.public_key()
            self._save_public_key()
    
    def _save_private_key(self):
        """Save private key to file"""
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(self.private_key_path, 'wb') as f:
            f.write(pem)
        print(f"✅ Private key saved to {self.private_key_path}")
    
    def _save_public_key(self):
        """Save public key to file"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.public_key_path, 'wb') as f:
            f.write(pem)
        print(f"✅ Public key saved to {self.public_key_path}")
    
    def _create_bundle_hash(self, bundle_data: Dict[str, Any]) -> str:
        """Create SHA-256 hash of bundle data for signing"""
        # Create canonical JSON representation
        canonical_data = json.dumps(bundle_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_data.encode('utf-8')).hexdigest()
    
    def sign_bundle(self, bundle_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a policy bundle
        
        Args:
            bundle_data: Bundle data containing policies and metadata
            
        Returns:
            Signed bundle with signature
        """
        # Add bundle metadata if not present
        if 'metadata' not in bundle_data:
            bundle_data['metadata'] = {}
        
        # Update metadata
        bundle_data['metadata'].update({
            'bundle_id': bundle_data.get('metadata', {}).get('bundle_id', f"bundle-{int(time.time())}"),
            'version': bundle_data.get('metadata', {}).get('version', '1.0.0'),
            'issued_at': datetime.now(timezone.utc).isoformat(),
            'issuer': 'unison-policy-signer',
            'algorithm': 'RSA-SHA256'
        })
        
        # Create hash of bundle data (excluding signature)
        bundle_hash = self._create_bundle_hash(bundle_data)
        
        # Sign the hash
        signature = self.private_key.sign(
            bundle_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Add signature to bundle
        bundle_data['signature'] = {
            'algorithm': 'RSA-PSS-SHA256',
            'key_id': 'policy-signer-key-1',
            'signature_b64': base64.b64encode(signature).decode('utf-8'),
            'hash': bundle_hash
        }
        
        return bundle_data
    
    def verify_bundle(self, bundle_data: Dict[str, Any]) -> bool:
        """
        Verify a signed policy bundle
        
        Args:
            bundle_data: Bundle data to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Extract signature
            signature_data = bundle_data.get('signature')
            if not signature_data:
                print("❌ No signature found in bundle")
                return False
            
            # Recreate hash (excluding signature field)
            bundle_copy = bundle_data.copy()
            bundle_copy.pop('signature', None)
            expected_hash = self._create_bundle_hash(bundle_copy)
            
            # Verify hash matches
            if signature_data.get('hash') != expected_hash:
                print("❌ Bundle hash mismatch")
                return False
            
            # Verify signature
            signature = base64.b64decode(signature_data['signature_b64'])
            self.public_key.verify(
                signature,
                expected_hash.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("✅ Bundle signature verified")
            return True
            
        except InvalidSignature:
            print("❌ Invalid signature")
            return False
        except Exception as e:
            print(f"❌ Verification error: {e}")
            return False
    
    def create_bundle_from_rules(self, rules_file: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a policy bundle from a rules YAML file
        
        Args:
            rules_file: Path to rules.yaml file
            metadata: Additional metadata for the bundle
            
        Returns:
            Policy bundle ready for signing
        """
        # Load rules
        with open(rules_file, 'r') as f:
            rules = yaml.safe_load(f) or []
        
        # Create bundle structure
        bundle = {
            'policies': rules,
            'metadata': metadata or {}
        }
        
        return bundle
    
    def save_bundle(self, bundle: Dict[str, Any], output_path: str):
        """Save signed bundle to file"""
        with open(output_path, 'w') as f:
            json.dump(bundle, f, indent=2, sort_keys=True)
        print(f"✅ Bundle saved to {output_path}")
    
    def load_bundle(self, bundle_path: str) -> Dict[str, Any]:
        """Load bundle from file"""
        with open(bundle_path, 'r') as f:
            return json.load(f)

def create_example_rules():
    """Create example policy rules for demonstration"""
    example_rules = [
        {
            "id": "unison.echo",
            "name": "Echo Capability",
            "description": "Allow users to use the echo skill",
            "effect": "allow",
            "conditions": {
                "required_scopes": ["unison.echo"],
                "allowed_purposes": ["voice_assistant", "testing"],
                "time_restrictions": {
                    "start": "00:00",
                    "end": "23:59"
                }
            }
        },
        {
            "id": "unison.storage.write",
            "name": "Storage Write",
            "description": "Allow writing to storage",
            "effect": "allow",
            "conditions": {
                "required_scopes": ["unison.storage.write"],
                "allowed_purposes": ["data_persistence", "backup"],
                "data_classification": ["public", "internal"]
            }
        },
        {
            "id": "unison.inference.text",
            "name": "Text Inference",
            "description": "Allow text-based inference",
            "effect": "allow",
            "conditions": {
                "required_scopes": ["unison.inference.text"],
                "allowed_purposes": ["content_analysis", "summarization"],
                "max_tokens": 1000
            }
        },
        {
            "id": "unison.sensitive.operations",
            "name": "Sensitive Operations",
            "description": "Require confirmation for sensitive operations",
            "effect": "require_confirmation",
            "conditions": {
                "required_scopes": ["unison.admin"],
                "allowed_purposes": ["system_administration"],
                "requires_elevated_privileges": True
            }
        }
    ]
    
    with open("example_rules.yaml", 'w') as f:
        yaml.dump(example_rules, f, default_flow_style=False, indent=2)
    
    print("✅ Example rules created in example_rules.yaml")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Policy Bundle Signer")
    parser.add_argument("command", choices=["sign", "verify", "create-example", "generate-keys"])
    parser.add_argument("--input", "-i", help="Input file (rules.yaml or bundle.json)")
    parser.add_argument("--output", "-o", help="Output file (bundle.json)")
    parser.add_argument("--metadata", "-m", help="Metadata JSON string")
    parser.add_argument("--private-key", help="Private key path")
    parser.add_argument("--public-key", help="Public key path")
    
    args = parser.parse_args()
    
    # Initialize signer
    signer = PolicyBundleSigner(
        private_key_path=args.private_key,
        public_key_path=args.public_key
    )
    
    if args.command == "sign":
        if not args.input:
            print("❌ Input file required for signing")
            return
        
        # Parse metadata if provided
        metadata = {}
        if args.metadata:
            try:
                metadata = json.loads(args.metadata)
            except json.JSONDecodeError:
                print("❌ Invalid metadata JSON")
                return
        
        # Create bundle from rules
        if args.input.endswith('.yaml') or args.input.endswith('.yml'):
            bundle = signer.create_bundle_from_rules(args.input, metadata)
        else:
            bundle = signer.load_bundle(args.input)
        
        # Sign bundle
        signed_bundle = signer.sign_bundle(bundle)
        
        # Save bundle
        output_path = args.output or "bundle.signed.json"
        signer.save_bundle(signed_bundle, output_path)
        
        print(f"🎉 Bundle signed successfully!")
        print(f"   Bundle ID: {signed_bundle['metadata']['bundle_id']}")
        print(f"   Version: {signed_bundle['metadata']['version']}")
        print(f"   Policies: {len(signed_bundle['policies'])}")
    
    elif args.command == "verify":
        if not args.input:
            print("❌ Input bundle file required for verification")
            return
        
        bundle = signer.load_bundle(args.input)
        if signer.verify_bundle(bundle):
            print("✅ Bundle is authentic and unmodified")
        else:
            print("❌ Bundle verification failed")
    
    elif args.command == "create-example":
        create_example_rules()
    
    elif args.command == "generate-keys":
        # Keys are generated during initialization
        print("✅ RSA key pair generated/loaded")
        print(f"   Private: {signer.private_key_path}")
        print(f"   Public: {signer.public_key_path}")

if __name__ == "__main__":
    main()
