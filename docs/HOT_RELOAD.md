# Policy Bundle Hot-Reload

## Overview

The policy service supports atomic hot-reload of policy bundles without dropping requests or causing downtime. This allows you to update policies in production without restarting the service.

## Features

- **Atomic Swap**: Bundle changes are applied atomically - either all changes succeed or none do
- **Zero Downtime**: Service continues processing requests during reload
- **< 100ms Target**: Reload completes quickly (typically < 100ms for file I/O)
- **Automatic Rollback**: Invalid bundles are rejected and state is preserved
- **Thread-Safe**: Concurrent requests are handled safely during reload
- **Validation**: Bundles are validated before being applied
- **History Tracking**: Last 10 reload attempts are tracked
- **Metrics**: Comprehensive Prometheus metrics for monitoring

## Quick Start

### Trigger a Reload

```bash
# Reload from default bundle path
curl -X POST http://localhost:8083/reload \
  -H "Content-Type: application/json" \
  -d '{}'

# Reload from specific bundle
curl -X POST http://localhost:8083/reload \
  -H "Content-Type: application/json" \
  -d '{"bundle_path": "/path/to/bundle.signed.json"}'
```

### Check Reload Status

```bash
# Get reload history
curl http://localhost:8083/reload/history

# Get reload statistics
curl http://localhost:8083/reload/stats
```

## API Endpoints

### POST /reload

Trigger a hot-reload of the policy bundle.

**Request Body**:
```json
{
  "bundle_path": "/path/to/bundle.json"  // Optional, defaults to UNISON_POLICY_BUNDLE env var
}
```

**Response** (Success):
```json
{
  "success": true,
  "version": "2.0.0",
  "duration_ms": 45.23,
  "policies_loaded": 12,
  "error": null
}
```

**Response** (Failure):
```json
{
  "success": false,
  "version": "1.0.0",  // Current version (unchanged)
  "duration_ms": 23.45,
  "policies_loaded": 0,
  "error": "Bundle verification failed"
}
```

**Status Codes**:
- `200 OK` - Reload successful
- `404 Not Found` - Bundle file not found
- `500 Internal Server Error` - Reload failed (validation, signature, etc.)

### POST /bundle/reload

Alias for `/reload`. Same functionality.

### GET /reload/history

Get the history of the last 10 reload attempts.

**Response**:
```json
{
  "history": [
    {
      "timestamp": "2025-11-07T19:30:00Z",
      "version": "2.0.0",
      "success": true,
      "duration_ms": 45.23,
      "policies_loaded": 12,
      "error": null
    },
    {
      "timestamp": "2025-11-07T19:25:00Z",
      "version": null,
      "success": false,
      "duration_ms": 23.45,
      "policies_loaded": 0,
      "error": "Bundle verification failed"
    }
  ]
}
```

### GET /reload/stats

Get reload statistics.

**Response**:
```json
{
  "total_reloads": 15,
  "successful_reloads": 14,
  "failed_reloads": 1,
  "success_rate": 93.33,
  "avg_duration_ms": 42.15,
  "last_reload": {
    "timestamp": "2025-11-07T19:30:00Z",
    "version": "2.0.0",
    "success": true,
    "duration_ms": 45.23,
    "policies_loaded": 12,
    "error": null
  }
}
```

## How It Works

### 1. Load Phase (Outside Lock)

The new bundle is loaded and validated outside the critical section to minimize lock time:

```
1. Load bundle from file
2. Validate bundle structure
3. Verify signature
4. Extract policies
```

This phase can take time (file I/O, validation) but doesn't block requests.

### 2. Swap Phase (Inside Lock)

The actual state change happens atomically inside a thread lock:

```
1. Acquire lock
2. Save old state (for rollback)
3. Swap to new state
4. Release lock
```

This phase is very fast (< 1ms typically) so request blocking is minimal.

### 3. Rollback on Failure

If anything fails during the swap, the old state is restored:

```
try:
    swap_to_new_state()
except Exception:
    restore_old_state()
    raise
```

## Validation

Bundles are validated before being applied:

### Structure Validation
- Bundle must be a dictionary
- Must have `metadata` and `policies` fields
- Metadata must include: `bundle_id`, `version`, `issued_at`

### Policy Validation
- Policies must be a non-empty list
- Each policy must have `id` and `effect` fields
- Policies must be dictionaries

### Signature Validation
- Bundle must have a valid signature
- Signature must verify with the public key
- Bundle hash must match

### Example Validation Error

```json
{
  "success": false,
  "error": "Bundle contains no policies",
  "duration_ms": 15.23
}
```

## Monitoring

### Prometheus Metrics

The `/metrics` endpoint exposes comprehensive reload metrics:

```prometheus
# Total reload attempts
unison_policy_reload_total 15

# Successful reloads
unison_policy_reload_success_total 14

# Failed reloads
unison_policy_reload_failure_total 1

# Success rate (percentage)
unison_policy_reload_success_rate 93.33

# Average reload duration (seconds)
unison_policy_reload_duration_seconds 0.04215

# Current bundle version
unison_policy_bundle_version{version="2.0.0"} 1

# When bundle was loaded (Unix timestamp)
unison_policy_bundle_loaded_timestamp 1699384200
```

### Health Checks

The `/readyz` endpoint includes bundle information:

```json
{
  "ready": true,
  "bundle_version": "2.0.0",
  "bundle_loaded_at": "2025-11-07T19:30:00Z",
  "bundle_age_hours": 2.5,
  "bundle_stale": false
}
```

**Staleness Warning**: If `bundle_age_hours` > 24, `bundle_stale` will be `true`.

## Best Practices

### 1. Test Bundles Before Deploying

Always test bundles in a non-production environment first:

```bash
# Verify bundle signature
curl -X POST http://localhost:8083/bundle/verify \
  -H "Content-Type: application/json" \
  -d '{"bundle_path": "/path/to/new-bundle.json"}'
```

### 2. Monitor Reload Success

Set up alerts on reload failures:

```prometheus
# Alert if reload fails
alert: PolicyReloadFailed
expr: increase(unison_policy_reload_failure_total[5m]) > 0
```

### 3. Check Reload History

After deploying a new bundle, verify it loaded successfully:

```bash
curl http://localhost:8083/reload/history | jq '.[0]'
```

### 4. Gradual Rollout

For critical changes, consider:
1. Deploy to canary environment first
2. Monitor for issues
3. Gradually roll out to production

### 5. Keep Bundles Small

Smaller bundles reload faster. Consider:
- Removing unused policies
- Optimizing policy conditions
- Keeping bundle size < 1MB

## Troubleshooting

### Reload Takes Too Long

**Symptom**: `duration_ms` > 1000ms

**Possible Causes**:
- Large bundle file (> 10MB)
- Slow disk I/O
- Network-mounted filesystem

**Solutions**:
- Reduce bundle size
- Use local filesystem
- Optimize policy structure

### Reload Fails with "Bundle verification failed"

**Symptom**: `error: "Bundle verification failed"`

**Possible Causes**:
- Bundle signed with wrong key
- Bundle corrupted during transfer
- Bundle modified after signing

**Solutions**:
- Re-sign bundle with correct key
- Verify file integrity (checksum)
- Use secure transfer method

### Reload Fails with "Bundle contains no policies"

**Symptom**: `error: "Bundle contains no policies"`

**Possible Causes**:
- Empty policies array
- Policies not in correct format
- Bundle structure incorrect

**Solutions**:
- Verify bundle structure
- Ensure policies array is not empty
- Check bundle generation process

### Requests Dropped During Reload

**Symptom**: 5xx errors during reload

**This should not happen!** If you see this:
1. Check reload duration (should be < 100ms)
2. Check for thread safety issues
3. Report as a bug

## Security Considerations

### 1. Signature Verification

All bundles must be signed:
- Uses RSA-PSS with SHA-256
- 2048-bit keys minimum
- Signature verified before loading

### 2. Access Control

**TODO**: Add authentication to reload endpoint

Currently, the `/reload` endpoint is unauthenticated. In production:
- Use API gateway for authentication
- Restrict access to admin users only
- Use mTLS for service-to-service calls

### 3. Audit Logging

All reload attempts are logged:

```
INFO: Hot-reload successful: v2.0.0 (45.23ms, 12 policies)
ERROR: Hot-reload failed: Bundle verification failed (23.45ms)
```

## Advanced Usage

### Automated Reloads

You can set up automated reloads using cron or a file watcher:

```bash
# Watch for bundle changes and reload
inotifywait -m /path/to/bundles -e close_write |
while read path action file; do
    if [[ "$file" == *.signed.json ]]; then
        curl -X POST http://localhost:8083/reload \
          -H "Content-Type: application/json" \
          -d "{\"bundle_path\": \"$path/$file\"}"
    fi
done
```

### Blue-Green Deployment

For zero-downtime policy updates:

1. Deploy new bundle to staging
2. Test thoroughly
3. Hot-reload production services one by one
4. Monitor metrics
5. Rollback if issues detected

### Canary Testing

Test new policies on a subset of traffic:

1. Deploy new bundle to canary instance
2. Route 10% of traffic to canary
3. Monitor metrics
4. Gradually increase traffic
5. Hot-reload all instances when confident

## Performance

### Typical Reload Times

| Bundle Size | Policies | Duration |
|-------------|----------|----------|
| 10 KB       | 5        | ~30ms    |
| 100 KB      | 50       | ~50ms    |
| 1 MB        | 500      | ~100ms   |
| 10 MB       | 5000     | ~500ms   |

**Note**: Times include file I/O, validation, and signature verification.

### Lock Time

The critical section (thread lock) is typically < 1ms:
- State swap is in-memory
- No I/O operations
- No validation (done before lock)

### Concurrent Requests

The service can handle thousands of concurrent requests during reload:
- Read operations continue normally
- Lock is only held for state swap
- No requests are dropped

## Examples

### Example 1: Simple Reload

```bash
# Reload from default path
curl -X POST http://localhost:8083/reload

# Response
{
  "success": true,
  "version": "2.0.0",
  "duration_ms": 45.23,
  "policies_loaded": 12,
  "error": null
}
```

### Example 2: Reload with Custom Path

```bash
# Reload from custom path
curl -X POST http://localhost:8083/reload \
  -H "Content-Type: application/json" \
  -d '{"bundle_path": "/opt/policies/production-v2.signed.json"}'
```

### Example 3: Check Reload History

```bash
# Get last 3 reloads
curl http://localhost:8083/reload/history | jq '.history[:3]'
```

### Example 4: Monitor Reload Success Rate

```bash
# Get success rate
curl http://localhost:8083/reload/stats | jq '.success_rate'
```

### Example 5: Automated Deployment Script

```bash
#!/bin/bash
# deploy-policy.sh

BUNDLE_PATH=$1
POLICY_SERVICE="http://localhost:8083"

echo "Deploying bundle: $BUNDLE_PATH"

# Verify bundle first
echo "Verifying bundle..."
VERIFY_RESULT=$(curl -s -X POST "$POLICY_SERVICE/bundle/verify" \
  -H "Content-Type: application/json" \
  -d "{\"bundle_path\": \"$BUNDLE_PATH\"}")

if [[ $(echo $VERIFY_RESULT | jq -r '.valid') != "true" ]]; then
    echo "ERROR: Bundle verification failed"
    echo $VERIFY_RESULT | jq
    exit 1
fi

echo "Bundle verified successfully"

# Reload bundle
echo "Reloading bundle..."
RELOAD_RESULT=$(curl -s -X POST "$POLICY_SERVICE/reload" \
  -H "Content-Type: application/json" \
  -d "{\"bundle_path\": \"$BUNDLE_PATH\"}")

if [[ $(echo $RELOAD_RESULT | jq -r '.success') != "true" ]]; then
    echo "ERROR: Reload failed"
    echo $RELOAD_RESULT | jq
    exit 1
fi

echo "Reload successful!"
echo $RELOAD_RESULT | jq

# Check new version
NEW_VERSION=$(echo $RELOAD_RESULT | jq -r '.version')
echo "New version: $NEW_VERSION"

# Verify policies loaded
POLICIES_LOADED=$(echo $RELOAD_RESULT | jq -r '.policies_loaded')
echo "Policies loaded: $POLICIES_LOADED"

echo "Deployment complete!"
```

## FAQ

### Q: Will requests be dropped during reload?

**A**: No. The reload is atomic and thread-safe. Requests continue to be processed normally.

### Q: How long does a reload take?

**A**: Typically 30-100ms depending on bundle size. The critical section (lock time) is < 1ms.

### Q: What happens if a reload fails?

**A**: The old state is preserved. The service continues using the previous bundle.

### Q: Can I reload while the service is under load?

**A**: Yes. The service is designed to handle reloads under load without dropping requests.

### Q: How many reload attempts are tracked?

**A**: The last 10 reload attempts are kept in history.

### Q: Can I rollback to a previous bundle?

**A**: Yes. Just reload the previous bundle file.

### Q: Is the reload endpoint authenticated?

**A**: Not currently. Use an API gateway or add authentication for production use.

### Q: What if the bundle file is corrupted?

**A**: The reload will fail with a validation error. The old bundle remains active.

### Q: Can I reload multiple services at once?

**A**: Yes, but consider doing it gradually to minimize risk.

### Q: How do I know if a bundle is stale?

**A**: Check the `/readyz` endpoint. If `bundle_stale` is `true`, the bundle is > 24 hours old.

## See Also

- [Bundle Format](BUNDLE_FORMAT.md) - Bundle structure and signing
- [Policy API](../README.md) - Policy service API documentation
- [Monitoring](../README.md#monitoring) - Metrics and health checks
