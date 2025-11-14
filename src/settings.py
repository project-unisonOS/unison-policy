"""Typed configuration objects for the unison-policy service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SERVICE_ROOT = Path(__file__).resolve().parent.parent


def _env_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ConsentSettings:
    secret: str = "consent-secret-key"
    audience: str = "orchestrator"
    default_ttl_hours: int = 24
    issuer: str = "unison-consent"


@dataclass(frozen=True)
class RedisSettings:
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None


@dataclass(frozen=True)
class PolicyServiceSettings:
    rules_path: Path = SERVICE_ROOT / "rules.yaml"
    bundle_path: Path = SERVICE_ROOT / "bundle.signed.json"
    consent: ConsentSettings = field(default_factory=ConsentSettings)
    redis: RedisSettings = field(default_factory=RedisSettings)

    @classmethod
    def from_env(cls) -> "PolicyServiceSettings":
        return cls(
            rules_path=Path(os.getenv("UNISON_POLICY_RULES", str(SERVICE_ROOT / "rules.yaml"))),
            bundle_path=Path(os.getenv("UNISON_POLICY_BUNDLE", str(SERVICE_ROOT / "bundle.signed.json"))),
            consent=ConsentSettings(
                secret=os.getenv("UNISON_CONSENT_SECRET", "consent-secret-key"),
                audience=os.getenv("UNISON_CONSENT_AUDIENCE", "orchestrator"),
                default_ttl_hours=int(os.getenv("UNISON_CONSENT_DEFAULT_TTL_HOURS", "24")),
                issuer=os.getenv("UNISON_CONSENT_ISSUER", "unison-consent"),
            ),
            redis=RedisSettings(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")),
                password=os.getenv("REDIS_PASSWORD"),
            ),
        )


__all__ = ["PolicyServiceSettings", "ConsentSettings", "RedisSettings"]
