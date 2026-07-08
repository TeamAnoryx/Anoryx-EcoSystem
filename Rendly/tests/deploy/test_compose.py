"""Compose threat-model tests (R-010, ADR-0010 Fork D).

Static YAML assertions on docker-compose.yml (no Docker daemon required). Mirrors
Anoryx-AI-Orchestrator's tests/deploy/test_compose.py (O-008, ADR-0008).
"""

from __future__ import annotations

from pathlib import Path

import yaml

_RENDLY_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _RENDLY_ROOT / "docker-compose.yml"

_SECRET_NAMES = ("postgres_password", "rendly_jwt_private_key_pem")
_FORBIDDEN_ENV = (
    "POSTGRES_PASSWORD",
    "RENDLY_JWT_PRIVATE_KEY_PEM",
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


def test_rendly_app_uses_file_secrets_not_env_passwords():
    c = _compose()
    app = c["services"]["rendly-app"]
    assert set(_SECRET_NAMES).issubset(set(app["secrets"])), "rendly-app must mount the secrets"
    env_keys = _env_keys(app)
    for forbidden in _FORBIDDEN_ENV:
        assert forbidden not in env_keys, f"rendly-app env must NOT contain {forbidden}"


def test_top_level_secrets_are_file_based():
    c = _compose()
    secrets = c["secrets"]
    for name in _SECRET_NAMES:
        assert name in secrets, f"missing top-level secret {name}"
        assert "file" in secrets[name], f"secret {name} must be file-based"


def test_postgres_service_and_volume_present():
    c = _compose()
    assert c["services"]["postgres"]["image"] == "postgres:16-alpine"
    assert "rendly-postgres-data" in c["volumes"]


def test_rendly_app_depends_on_postgres_healthy():
    c = _compose()
    app = c["services"]["rendly-app"]
    assert app["depends_on"]["postgres"]["condition"] == "service_healthy"
