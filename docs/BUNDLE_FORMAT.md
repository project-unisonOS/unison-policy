# Policy Bundle Format

## Overview

Policy bundles are signed JSON files that contain policies, metadata, and cryptographic signatures. They are used to distribute and verify policies across the Unison platform.

## Bundle Structure

A policy bundle has three main sections:

```json
{
  "metadata": { ... },
  "policies": [ ... ],
  "signature": { ... }
}
```

## Metadata Section

The metadata section contains information about the bundle:

```json
{
  "metadata": {
    "bundle_id": "policy-bundle-v2.0.0",
    "version": "2.0.0",
    "issued_at": "2025-11-07T19:30:00Z",
    "issuer": "unison-policy-signer",
    "algorithm": "RSA-SHA256",
    "description": "Production policies for Q4 2025"
  }
}
```

### Required Fields

- **bundle_id** (string): Unique identifier for this bundle
- **version** (string): Semantic version (e.g., "2.0.0")
- **issued_at** (string): ISO 8601 timestamp when bundle was created

### Optional Fields

- **issuer** (string): Who created the bundle
- **algorithm** (string): Signing algorithm used
- **description** (string): Human-readable description
- **expires_at** (string): ISO 8601 timestamp when bundle expires
- **tags** (array): Tags for categorization

## Policies Section

The policies section contains an array of policy objects:

```json
{
  "policies": [
    {
      "id": "allow-public-read",
      "effect": "allow",
      "description": "Allow public read access",
      "conditions": {
        "data_classification": "public",
        "time_restrictions": {
          "start": "00:00",
          "end": "23:59"
        }
      },
      "priority": 100
    }
  ]
}
```

### Policy Fields

#### Required

- **id** (string): Unique policy identifier
- **effect** (string): "allow", "deny", or "require_confirmation"

#### Optional

- **description** (string): Human-readable description
- **conditions** (object): Conditions for policy application
- **priority** (number): Higher priority policies are evaluated first
- **enabled** (boolean): Whether policy is active (default: true)

### Conditions

Conditions determine when a policy applies:

```json
{
  "conditions": {
    "data_classification": "confidential",
    "time_restrictions": {
      "start": "09:00",
      "end": "17:00"
    },
    "allowed_persons": ["user123", "user456"],
    "required_scopes": ["read", "write"]
  }
}
```

## Signature Section

The signature section contains cryptographic verification data:

```json
{
  "signature": {
    "algorithm": "RSA-PSS-SHA256",
    "key_id": "policy-signer-key-1",
    "signature_b64": "base64-encoded-signature...",
    "hash": "sha256-hash-of-bundle-data"
  }
}
```

### Signature Fields

- **algorithm** (string): Signature algorithm (RSA-PSS-SHA256)
- **key_id** (string): Identifier for the signing key
- **signature_b64** (string): Base64-encoded signature
- **hash** (string): SHA-256 hash of bundle data (excluding signature)

## Complete Example

```json
{
  "metadata": {
    "bundle_id": "production-policies-2025-q4",
    "version": "2.1.0",
    "issued_at": "2025-11-07T19:30:00Z",
    "issuer": "policy-admin",
    "algorithm": "RSA-SHA256",
    "description": "Production policies with new data classification rules"
  },
  "policies": [
    {
      "id": "allow-public-read",
      "effect": "allow",
      "description": "Allow read access to public data",
      "conditions": {
        "data_classification": "public"
      },
      "priority": 100
    },
    {
      "id": "require-confirmation-confidential",
      "effect": "require_confirmation",
      "description": "Require user confirmation for confidential data",
      "conditions": {
        "data_classification": "confidential"
      },
      "priority": 200
    },
    {
      "id": "deny-secret-after-hours",
      "effect": "deny",
      "description": "Deny access to secret data outside business hours",
      "conditions": {
        "data_classification": "secret",
        "time_restrictions": {
          "start": "09:00",
          "end": "17:00"
        }
      },
      "priority": 300
    }
  ],
  "signature": {
    "algorithm": "RSA-PSS-SHA256",
    "key_id": "policy-signer-key-1",
    "signature_b64": "iJKV1QiLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "hash": "a3c5f8d2e1b4c9a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3"
  }
}
```

## Creating a Bundle

### Using the Bundle Signer

```python
from bundle_signer import PolicyBundleSigner

# Initialize signer
signer = PolicyBundleSigner(
    private_key_path="keys/private_key.pem",
    public_key_path="keys/public_key.pem"
)

# Create bundle data
bundle_data = {
    "metadata": {
        "bundle_id": "my-bundle",
        "version": "1.0.0"
    },
    "policies": [
        {
            "id": "policy-1",
            "effect": "allow",
            "description": "My first policy"
        }
    ]
}

# Sign bundle
signed_bundle = signer.sign_bundle(bundle_data)

# Save to file
import json
with open("bundle.signed.json", "w") as f:
    json.dump(signed_bundle, f, indent=2)
```

### From YAML Rules

```python
# Create bundle from existing YAML rules
bundle = signer.create_bundle_from_rules(
    rules_file="rules.yaml",
    metadata={
        "bundle_id": "converted-rules",
        "version": "1.0.0",
        "description": "Converted from YAML"
    }
)

# Sign and save
signed_bundle = signer.sign_bundle(bundle)
with open("bundle.signed.json", "w") as f:
    json.dump(signed_bundle, f, indent=2)
```

## Verifying a Bundle

### Using the Bundle Signer (CI/CD example)

```python
from bundle_signer import PolicyBundleSigner
import json

# Initialize signer
signer = PolicyBundleSigner(
    public_key_path="keys/public_key.pem"
)

# Load bundle
with open("bundle.signed.json", "r") as f:
    bundle = json.load(f)

# Verify signature
if signer.verify_bundle(bundle):
    print("✅ Bundle signature is valid")
else:
    print("❌ Bundle signature is invalid")
```

### Using the API

```bash
curl -X POST http://localhost:8083/bundle/verify \
  -H "Content-Type: application/json" \
  -d '{"bundle_path": "/path/to/bundle.signed.json"}'
```

## Versioning

### Semantic Versioning

Bundles should use semantic versioning:

- **Major** (X.0.0): Breaking changes to policy structure
- **Minor** (0.X.0): New policies added, backward compatible
- **Patch** (0.0.X): Bug fixes, clarifications

### Version Examples

- `1.0.0` - Initial release
- `1.1.0` - Added new policies
- `1.1.1` - Fixed policy description
- `2.0.0` - Changed policy structure (breaking)

### Version in Responses

All policy responses include the bundle version:

```json
{
  "capability_id": "read-data",
  "decision": {
    "allowed": true,
    "require_confirmation": false,
    "reason": "allow-public-read"
  },
  "policy_version": "2.1.0"
}
```

## Security

### Signing Keys

- Use RSA keys with minimum 2048 bits
- Store private keys securely (HSM, vault, encrypted storage)
- Rotate keys periodically
- Never commit private keys to version control

### Key Generation

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Set permissions
chmod 600 private_key.pem
chmod 644 public_key.pem
```

### Bundle Integrity

The signature ensures:
- Bundle has not been modified
- Bundle was created by authorized signer
- Bundle data matches the hash

### Verification Process

1. Extract signature from bundle
2. Recreate hash of bundle data (excluding signature)
3. Verify hash matches signature's hash
4. Verify signature using public key
5. If all checks pass, bundle is valid

## Best Practices

### 1. Use Descriptive IDs

```json
{
  "id": "allow-public-read-daytime",  // Good
  "id": "policy-1"                     // Bad
}
```

### 2. Add Descriptions

```json
{
  "id": "require-mfa-sensitive",
  "description": "Require MFA for sensitive data access during business hours",
  "effect": "require_confirmation"
}
```

### 3. Use Priority

Higher priority policies are evaluated first:

```json
{
  "id": "deny-all-secret",
  "priority": 1000,  // Evaluated first
  "effect": "deny"
},
{
  "id": "allow-public",
  "priority": 100,   // Evaluated later
  "effect": "allow"
}
```

### 4. Test Before Deploying

Always test bundles in a non-production environment:

```bash
# Verify bundle
curl -X POST http://staging:8083/bundle/verify \
  -d '{"bundle_path": "/path/to/bundle.json"}'

# Test reload
curl -X POST http://staging:8083/reload \
  -d '{"bundle_path": "/path/to/bundle.json"}'

# Verify policies work
curl -X POST http://staging:8083/evaluate \
  -d '{"capability_id": "test", "context": {}}'
```

### 5. Version Control Bundles

Store bundle source (before signing) in version control:

```
policies/
  ├── v1.0.0/
  │   ├── bundle.json          # Unsigned
  │   └── bundle.signed.json   # Signed
  ├── v1.1.0/
  │   ├── bundle.json
  │   └── bundle.signed.json
  └── current -> v1.1.0/
```

### 6. Document Changes

Include a changelog in the bundle description or separate file:

```json
{
  "metadata": {
    "version": "2.1.0",
    "description": "Added data classification policies, fixed time window bug"
  }
}
```

## Validation Rules

### Bundle Level

- Must be valid JSON
- Must have `metadata`, `policies`, and `signature` sections
- Metadata must include `bundle_id`, `version`, `issued_at`
- Policies must be a non-empty array
- Signature must be valid

### Policy Level

- Each policy must have `id` and `effect`
- `effect` must be "allow", "deny", or "require_confirmation"
- `id` must be unique within bundle
- Conditions must be valid objects

### Signature Level

- Algorithm must be RSA-PSS-SHA256
- Signature must be base64-encoded
- Hash must match bundle data
- Signature must verify with public key

## Troubleshooting

### "Bundle verification failed"

**Cause**: Signature doesn't match

**Solutions**:
- Verify bundle was signed with correct key
- Check bundle wasn't modified after signing
- Re-sign bundle

### "Bundle contains no policies"

**Cause**: Policies array is empty

**Solutions**:
- Add at least one policy
- Check bundle generation process

### "Policy X missing 'id' field"

**Cause**: Policy doesn't have required `id` field

**Solutions**:
- Add `id` field to all policies
- Verify bundle structure

### "Invalid signature format"

**Cause**: Signature is not properly base64-encoded

**Solutions**:
- Re-sign bundle
- Check signing process

## Migration

### From YAML to Bundle

If you're currently using YAML rules:

```python
from bundle_signer import PolicyBundleSigner

signer = PolicyBundleSigner()

# Convert YAML to bundle
bundle = signer.create_bundle_from_rules(
    rules_file="rules.yaml",
    metadata={
        "bundle_id": "migrated-from-yaml",
        "version": "1.0.0"
    }
)

# Sign and save
signed = signer.sign_bundle(bundle)
with open("bundle.signed.json", "w") as f:
    json.dump(signed, f, indent=2)
```

### Gradual Migration

1. Keep YAML as fallback
2. Deploy signed bundles
3. Test thoroughly
4. Remove YAML once confident

## See Also

- [Hot-Reload Documentation](HOT_RELOAD.md) - How to reload bundles
- [Policy API](../README.md) - Policy service API
- [Security Best Practices](../README.md#security) - Security guidelines
