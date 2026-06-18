"""Compose threat-model + R3-freeze tests (F-010, ADR-0012 §9 vector 8).

Static YAML assertions on docker-compose.yml (no Docker daemon required):

  8  test_sentinel_app_uses_file_secrets_not_env_passwords — no *_PASSWORD/secret in env
     + top-level secrets are file-based + sentinel-app mounts them.
  R3 test_frozen_services_unchanged — redis/postgres/volumes sections untouched.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_SENTINEL_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _SENTINEL_ROOT / "docker-compose.yml"

_SECRET_NAMES = ("postgres_password", "redis_password", "sentinel_key_secret")
_FORBIDDEN_ENV = (
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "SENTINEL_KEY_SECRET",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
)


def _compose() -> dict:
    return yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))


def _env_keys(service: dict) -> set[str]:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return {k.upper() for k in env}
    return {str(e).split("=", 1)[0].upper() for e in env}


# --------------------------------------------------------------------------- #
# Vector 8 — secrets are file-mounted, never environment variables.           #
# --------------------------------------------------------------------------- #
def test_sentinel_app_uses_file_secrets_not_env_passwords():
    c = _compose()
    app = c["services"]["sentinel-app"]
    assert set(_SECRET_NAMES).issubset(set(app["secrets"])), "sentinel-app must mount the secrets"
    env_keys = _env_keys(app)
    for forbidden in _FORBIDDEN_ENV:
        assert (
            forbidden not in env_keys
        ), f"sentinel-app env must NOT contain {forbidden} (vector 8)"


def test_top_level_secrets_are_file_based():
    c = _compose()
    secrets = c["secrets"]
    for name in _SECRET_NAMES:
        assert name in secrets, f"missing top-level secret {name}"
        assert "file" in secrets[name], f"secret {name} must be file-based (β)"


# --------------------------------------------------------------------------- #
# R3 — the F-009 services / networks / volumes are frozen.                    #
# --------------------------------------------------------------------------- #
def test_frozen_services_unchanged():
    c = _compose()
    assert c["services"]["redis"]["image"] == "redis:7-alpine"
    assert c["services"]["postgres"]["image"] == "postgres:16-alpine"
    # redis service must remain password-less (no requirepass added — R3).
    assert "requirepass" not in str(c["services"]["redis"].get("command", ""))
    # No new named volumes were added to the frozen volumes section.
    assert set(c["volumes"].keys()) == {"redis-data", "sentinel-postgres-data"}


# --------------------------------------------------------------------------- #
# New services wired correctly.                                               #
# --------------------------------------------------------------------------- #
def test_otel_collector_and_caddy_present():
    c = _compose()
    assert "otel-collector" in c["services"]
    caddy = c["services"]["caddy"]
    assert "tls" in caddy.get("profiles", []), "caddy must be gated behind the tls profile"


def test_sentinel_app_wires_otel_and_depends_on_db():
    c = _compose()
    app = c["services"]["sentinel-app"]
    assert app["environment"]["OTEL_EXPORTER_OTLP_ENDPOINT"].endswith(":4318")
    assert "postgres" in app["depends_on"] and "redis" in app["depends_on"]
