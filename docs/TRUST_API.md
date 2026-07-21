# Trust API v1

`POST /v1/trust/evaluate` is the authoritative Phase 3 decision boundary. Every
request names the principal, assistant, purpose, audiences, context space,
assurance level, data classes, action, channel, and recipients. Missing or
unknown dimensions return `deny`; no caller may interpret an error as consent.

Possible outcomes are `allow`, `deny`, `redact`, `minimize`, `ask`, and
`step-up`. A disclosure decision explains the action, consequence,
reversibility, disclosed and redacted fields, alternatives, and any required
assurance. `ask` returns a short-lived, request-bound confirmation identifier.
Confirmations are one-use and can expire or be cancelled.

Capability grants are explicit, versioned, revocable intersections of actions,
purposes, audiences, data classes, spaces, recipients, risk, cost, and execution
location. The credential endpoint stores an encrypted task credential and
returns only an opaque identifier; injection happens at execution time and the
plaintext is never included in planner, model, decision, or audit payloads.

## Simulator

Use synthetic data only:

```bash
PYTHONPATH=src:../unison-common/src python trust_simulator.py examples/trust-request.json
```

The simulator returns exit code 2 for denied or malformed requests.
