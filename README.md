# unison-policy

The policy service is the safety and consent gate for the Unison system, providing real-time policy evaluation, consent management, and comprehensive audit logging.

## Purpose

The policy service:
- Evaluates whether actions are allowed based on safety, consent, and authorization rules
- Captures and manages explicit consent for high-impact actions
- Maintains comprehensive audit logs of all policy decisions and actions
- Enforces privacy zones and data protection requirements
- Provides configurable rule engine for custom policies
- Supports emergency workflows and safety protocols

## Current Status

### ✅ Implemented
- FastAPI-based HTTP service with health endpoints
- Real-time policy evaluation engine with configurable rules
- Consent management with explicit capture and verification
- Comprehensive audit logging with correlation IDs
- Privacy zone enforcement and data protection
- Emergency workflow support and safety protocols
- Role-based access control for policy administration
- Integration with orchestrator for real-time decision making
- Structured logging and monitoring capabilities

### 🚧 In Progress
- Machine learning-based policy recommendations
- Advanced consent flow with biometric verification
- Cross-jurisdictional compliance frameworks
- Real-time threat detection and response

### 📋 Planned
- Adaptive policy learning from behavior patterns
- Integration with external compliance systems
- Advanced analytics for policy optimization
- Multi-tenant policy management

## Quick Start

### Local Development
```bash
# Clone and setup
git clone https://github.com/project-unisonOS/unison-policy
cd unison-policy

# Install dependencies
pip install -r requirements.txt

# Run with default policies
python src/server.py
```

### Docker Deployment
```bash
# Using the development stack
cd ../unison-devstack
docker-compose up -d policy

# Health check
curl http://localhost:8083/health
```

## API Reference

### Core Endpoints
- `GET /health` - Service health check
- `GET /ready` - Policy engine readiness check
- `POST /evaluate` - Evaluate policy for action
- `POST /consent` - Capture explicit consent
- `GET /consent/{consent_id}` - Retrieve consent status
- `POST /audit` - Log executed action
- `GET /audit` - Query audit logs
- `GET /rules` - List active policies
- `POST /rules` - Update policy rules (admin only)

### Policy Evaluation
```bash
# Evaluate action permission
curl -X POST http://localhost:8083/evaluate \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "send_message",
    "context": {
      "recipient": "contact-123",
      "person_id": "person-456",
      "privacy_zone": "work"
    },
    "consent_required": true
  }'

# Capture consent
curl -X POST http://localhost:8083/consent \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "person_id": "person-456",
    "action": "send_message",
    "consent_type": "explicit",
    "verification": "biometric",
    "expires_at": "2024-01-01T13:00:00Z"
  }'
```

[Full API Documentation](../../unison-docs/developer/api-reference/policy.md)

## Configuration

### Environment Variables
```bash
# Service Configuration
POLICY_PORT=8083                     # Service port
POLICY_HOST=0.0.0.0                  # Service host

# Policy Engine
POLICY_RULES_PATH=/config/rules.json # Policy rules file
POLICY_DEFAULT_ACTION=deny           # Default action for undefined rules
POLICY_CACHE_TTL=300                 # Policy decision cache TTL

# Consent Management
POLICY_CONSENT_TTL=3600              # Consent expiration (seconds)
POLICY_CONSENT_STORAGE=database      # Consent storage backend
POLICY_BIOMETRIC_ENABLED=true        # Enable biometric verification

# Audit and Logging
POLICY_AUDIT_RETENTION_DAYS=2555     # Audit log retention (7 years)
POLICY_LOG_LEVEL=INFO                # Logging verbosity
POLICY_ENABLE_METRICS=true           # Enable metrics collection

# Safety and Emergency
POLICY_EMERGENCY_CONTACTS=emergency@unisonos.org
POLICY_SAFETY_TIMEOUTS=30            # Safety check timeouts
```

## Policy Rules

### Rule Structure
```json
{
  "rules": [
    {
      "id": "send_message_policy",
      "name": "Message Sending Policy",
      "description": "Controls who can send messages to whom",
      "conditions": {
        "action": "send_message",
        "privacy_zones": ["work", "public"],
        "time_restrictions": {
          "allowed_hours": ["09:00-17:00"],
          "timezone": "person_timezone"
        }
      },
      "actions": {
        "allow": true,
        "consent_required": true,
        "verification": "explicit",
        "audit_level": "high"
      },
      "exceptions": [
        {
          "condition": "emergency_contact",
          "action": "allow_immediate"
        }
      ]
    }
  ]
}
```

### High-Impact Actions
The policy service manages consent for:
- **Communication**: Sending messages, emails, making calls
- **Location Sharing**: Sharing current location or location history
- **Financial Actions**: Payments, transfers, purchase approvals
- **Emergency Workflows**: Calling for help, alerting contacts
- **Data Sharing**: Sharing personal data with third parties
- **System Changes**: Modifying system settings or preferences

## Development

### Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Load test policies
python scripts/load_test_policies.py

# Run tests
pytest tests/

# Run with debug logging
LOG_LEVEL=DEBUG python src/server.py
```

### Testing
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Policy engine tests
pytest tests/policy/

# Consent flow tests
pytest tests/consent/

# Security tests
pytest tests/security/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes with comprehensive tests
4. Ensure all policy and security tests pass
5. Submit a pull request with detailed description

[Development Guide](../../unison-docs/developer/contributing.md)

## Security and Privacy

### Policy Enforcement
- **Real-time Evaluation**: Sub-millisecond policy decisions
- **Context-Aware Rules**: Policies adapt to context and environment
- **Consent Verification**: Multi-factor consent verification
- **Audit Trail**: Complete audit trail for all decisions
- **Privacy Zones**: Enforce location and context-based privacy

### Consent Management
- **Explicit Consent**: Clear, informed consent for all actions
- **Granular Control**: Fine-grained consent for different action types
- **Revocation**: Instant consent revocation and action cancellation
- **Biometric Verification**: Optional biometric consent verification
- **Consent History**: Complete history of consent decisions

### Compliance
- **GDPR Compliance**: Explicit consent management and right to withdraw
- **Audit Requirements**: Comprehensive audit logging for compliance
- **Data Protection**: Privacy by design in all policy decisions
- **Safety Standards**: Emergency and safety protocol compliance

[Security Documentation](../../unison-docs/operations/security.md)

## Architecture

### Policy Service Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Layer     │───▶│  Policy Engine   │───▶│  Rule Manager   │
│ (FastAPI)       │    │ (Evaluator)      │    │ (Rules & Logic) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Consent Manager  │
                       │ (Capture &       │
                       │  Verification)   │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Audit Layer    │
                       │ (Logging &       │
                       │  Compliance)     │
                       └──────────────────┘
```

### Decision Flow
1. **Request**: Service requests policy evaluation
2. **Context Analysis**: Analyze action context and conditions
3. **Rule Evaluation**: Apply relevant policy rules
4. **Consent Check**: Determine if consent is required
5. **Decision**: Return allow/deny with reasoning
6. **Audit**: Log decision for compliance

[Architecture Documentation](../../unison-docs/developer/architecture.md)

## Monitoring

### Health Checks
- `/health` - Basic service health
- `/ready` - Policy engine and rules readiness
- `/metrics` - Policy operation metrics

### Metrics
Key metrics available:
- Policy evaluations per second
- Consent requests and grants
- Audit log volume
- Rule cache hit rates
- Decision latency by rule type
- Safety protocol activations

### Logging
Structured JSON logging with correlation IDs:
- Policy decisions and reasoning
- Consent capture and verification
- Safety protocol activations
- Rule changes and updates
- Compliance and audit events

[Monitoring Guide](../../unison-docs/operations/monitoring.md)

## Emergency and Safety

### Emergency Workflows
```bash
# Trigger emergency protocol
curl -X POST http://localhost:8083/emergency \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "person_id": "person-456",
    "emergency_type": "medical",
    "location": {"lat": 40.7128, "lon": -74.0060},
    "contacts": ["emergency-123", "contact-456"]
  }'

# Check safety status
curl -X GET http://localhost:8083/safety/person-456 \
  -H "Authorization: Bearer <access-token>"
```

### Safety Features
- **Emergency Contacts**: Pre-configured emergency contact lists
- **Location Sharing**: Automatic location sharing in emergencies
- **Safety Check-ins**: Regular safety check-in protocols
- **Alert Systems**: Multi-channel alert notifications
- **Escalation Protocols**: Automatic escalation for non-responsive situations

## Related Services

### Dependencies
- **unison-auth** - Authentication and authorization
- **unison-orchestrator** - Primary policy consumer
- **unison-context** - Context for policy evaluation

### Consumers
- **unison-orchestrator** - Real-time policy evaluation
- **unison-inference** - Content policy enforcement
- **I/O modules** - Action permission checks
- **External services** - Third-party policy compliance

## Troubleshooting

### Common Issues

**Policy Evaluation Failures**
```bash
# Check service health
curl http://localhost:8083/health

# Verify rules are loaded
curl -X GET http://localhost:8083/rules \
  -H "Authorization: Bearer <token>"

# Check rule syntax
python scripts/validate_rules.py /config/rules.json
```

**Consent Issues**
```bash
# Check consent status
curl -X GET http://localhost:8083/consent/consent-123 \
  -H "Authorization: Bearer <token>"

# Test consent flow
python scripts/test_consent.py --person-id person-456
```

**Performance Issues**
```bash
# Check policy metrics
curl http://localhost:8083/metrics

# Monitor rule evaluation performance
docker-compose logs policy | grep "evaluation_time"
```

### Debug Mode
```bash
# Enable verbose logging
LOG_LEVEL=DEBUG POLICY_DEBUG_RULES=true python src/server.py

# Monitor policy decisions
docker-compose logs -f policy | jq '.'

# Test policy engine
python scripts/test_policy.py --all
```

[Troubleshooting Guide](../../unison-docs/people/troubleshooting.md)

## Version Compatibility

| Policy Version | Unison Common | Auth Service | Minimum Docker |
|-----------------|---------------|--------------|----------------|
| 1.0.0           | 1.0.0         | 1.0.0        | 20.10+         |
| 0.9.x           | 0.9.x         | 0.9.x        | 20.04+         |

[Compatibility Matrix](../../unison-spec/specs/version-compatibility.md)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [Project Unison Docs](https://github.com/project-unisonOS/unison-docs)
- **Issues**: [GitHub Issues](https://github.com/project-unisonOS/unison-policy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/project-unisonOS/unison-policy/discussions)
- **Security**: Report security issues to security@unisonos.org
