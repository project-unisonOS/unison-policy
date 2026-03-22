# unison-policy

Runtime policy, grant, bundle, and rule-management service for UnisonOS.

## Status
Core service (active). The implementation is a FastAPI app in `src/server.py` backed by `rules.yaml`, signed bundle files, and optional Redis settings from `src/settings.py`.

## What is implemented
- Policy evaluation via `POST /evaluate`.
- Rule inspection and replacement via `GET /rules`, `POST /rules`, and `GET /rules/summary`.
- Signed bundle inspection, reload, and verification endpoints.
- Consent/grant issuance, revocation, introspection, and statistics endpoints.
- Health, readiness, and Prometheus-style metrics endpoints.
- Hot-reload history and reload metrics.

## API surface
- `GET /health`, `GET /healthz`
- `GET /ready`, `GET /readyz`
- `GET /metrics`
- `GET /rules`
- `POST /rules`
- `GET /rules/summary`
- `POST /evaluate`
- `GET /bundle`
- `POST /reload`
- `POST /bundle/reload`
- `POST /bundle/verify`
- `GET /bundle/policies`
- `GET /reload/history`
- `GET /reload/stats`
- `POST /grants`
- `POST /grants/{jti}/revoke`
- `POST /grants/introspect`
- `GET /grants/stats`

## Run locally
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
cp .env.example .env
python src/server.py
```

## Key configuration
- `UNISON_POLICY_RULES`
- `UNISON_POLICY_BUNDLE`
- `UNISON_CONSENT_SECRET`
- `UNISON_CONSENT_AUDIENCE`
- `UNISON_CONSENT_DEFAULT_TTL_HOURS`
- `UNISON_CONSENT_ISSUER`
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`

## Supporting files
- `rules.yaml` — default live rule set
- `bundle.signed.json` and `production-bundle.json` — bundle inputs/examples
- `docs/BUNDLE_FORMAT.md`
- `docs/HOT_RELOAD.md`

## Tests
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -c ../constraints.txt -r requirements.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 OTEL_SDK_DISABLED=true python -m pytest
```
