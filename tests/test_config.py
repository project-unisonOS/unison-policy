from __future__ import annotations

from pathlib import Path

from src.settings import PolicyServiceSettings


def test_policy_settings_defaults(monkeypatch):
    env_keys = [
        "UNISON_POLICY_RULES",
        "UNISON_POLICY_BUNDLE",
        "UNISON_CONSENT_SECRET",
        "UNISON_CONSENT_AUDIENCE",
        "UNISON_CONSENT_DEFAULT_TTL_HOURS",
        "UNISON_CONSENT_ISSUER",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_PASSWORD",
    ]
    for key in env_keys:
        monkeypatch.delenv(key, raising=False)

    settings = PolicyServiceSettings.from_env()

    service_root = Path(__file__).resolve().parents[1]
    assert settings.rules_path == service_root / "rules.yaml"
    assert settings.bundle_path == service_root / "bundle.signed.json"
    assert settings.consent.secret == "consent-secret-key"
    assert settings.consent.audience == "orchestrator"
    assert settings.consent.default_ttl_hours == 24
    assert settings.consent.issuer == "unison-consent"
    assert settings.redis.host == "localhost"
    assert settings.redis.port == 6379
    assert settings.redis.password is None


def test_policy_settings_env_overrides(monkeypatch):
    overrides = {
        "UNISON_POLICY_RULES": "/tmp/rules.yaml",
        "UNISON_POLICY_BUNDLE": "/tmp/bundle.signed.json",
        "UNISON_CONSENT_SECRET": "secret",
        "UNISON_CONSENT_AUDIENCE": "testing",
        "UNISON_CONSENT_DEFAULT_TTL_HOURS": "12",
        "UNISON_CONSENT_ISSUER": "custom-issuer",
        "REDIS_HOST": "redis-host",
        "REDIS_PORT": "6380",
        "REDIS_PASSWORD": "redis-pass",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)

    settings = PolicyServiceSettings.from_env()

    assert settings.rules_path == Path("/tmp/rules.yaml")
    assert settings.bundle_path == Path("/tmp/bundle.signed.json")
    assert settings.consent.secret == "secret"
    assert settings.consent.audience == "testing"
    assert settings.consent.default_ttl_hours == 12
    assert settings.consent.issuer == "custom-issuer"
    assert settings.redis.host == "redis-host"
    assert settings.redis.port == 6380
    assert settings.redis.password == "redis-pass"
