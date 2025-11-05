#!/usr/bin/env python3
"""
Simple bundle verification demo
"""

import json
import sys
from pathlib import Path

def show_bundle_info(bundle_path):
    """Display bundle information"""
    try:
        with open(bundle_path, 'r') as f:
            bundle = json.load(f)
        
        print(f"📦 Bundle: {bundle_path}")
        print("=" * 50)
        
        # Show metadata
        metadata = bundle.get('metadata', {})
        print(f"📋 Metadata:")
        print(f"   ID: {metadata.get('bundle_id')}")
        print(f"   Version: {metadata.get('version')}")
        print(f"   Description: {metadata.get('description')}")
        print(f"   Issued: {metadata.get('issued_at')}")
        print(f"   Issuer: {metadata.get('issuer')}")
        
        # Show signature info
        signature = bundle.get('signature', {})
        print(f"\n🔐 Signature:")
        print(f"   Algorithm: {signature.get('algorithm')}")
        print(f"   Key ID: {signature.get('key_id')}")
        print(f"   Hash: {signature.get('hash')[:16]}...")
        
        # Show policies
        policies = bundle.get('policies', [])
        print(f"\n📜 Policies ({len(policies)}):")
        for policy in policies:
            print(f"   • {policy.get('id')}: {policy.get('effect')}")
            print(f"     {policy.get('description')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error reading bundle: {e}")
        return False

def main():
    """Main demo"""
    print("🔐 Policy Bundle Signer Demo")
    print("=" * 50)
    
    bundles = [
        "bundle.signed.json",
        "production-bundle.json",
        "bundle.example.json"
    ]
    
    for bundle in bundles:
        if Path(bundle).exists():
            print(f"\n")
            show_bundle_info(bundle)
        else:
            print(f"\n❌ Bundle not found: {bundle}")
    
    print(f"\n🎉 Demo completed!")
    print(f"\n📁 Available files:")
    print(f"   • keys/private_key.pem - RSA private key")
    print(f"   • keys/public_key.pem - RSA public key")
    print(f"   • example_rules.yaml - Example policy rules")
    print(f"   • bundle.signed.json - Demo signed bundle")
    print(f"   • production-bundle.json - Production signed bundle")

if __name__ == "__main__":
    main()
