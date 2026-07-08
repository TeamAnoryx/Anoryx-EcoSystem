"""Compose threat-model tests (O-008, ADR-0008 Fork D).

Static YAML assertions on docker-compose.yml (no Docker daemon required).
Mirrors Anoryx-Sentinel's tests/deploy/test_compose.py (F-010, ADR-0012 §9
vector 8): secrets are file-mounted, never environment variables.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_ORCH_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ORCH_ROOT / "docker-compose.yml"

_SECRET_NAMES = ("postgres_password", "orch_ingest_hmac_secret", "orch_admin_token")
_FORBIDDEN_ENV = (
    "POSTGRES_PASSWORD",
    "ORCH_INGEST_HMAC_SECRET",
    "ORCH_ADMIN_TOKEN",
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


def test_orchestrator_app_uses_file_secrets_not_env_passwords():
    c = _compose()
    app = c["services"]["orchestrator-app"]
    assert set(_SECRET_NAMES).issubset(
        set(app["secrets"])
    ), "orchestrator-app must mount the secrets"
    env_keys = _env_keys(app)
    for forbidden in _FORBIDDEN_ENV:
        assert forbidden not in env_keys, f"orchestrator-app env must NOT contain {forbidden}"


def test_top_level_secrets_are_file_based():
    c = _compose()
    secrets = c["secrets"]
    for name in _SECRET_NAMES:
        assert name in secrets, f"missing top-level secret {name}"
        assert "file" in secrets[name], f"secret {name} must be file-based"


def test_postgres_service_and_volume_present():
    c = _compose()
    assert c["services"]["postgres"]["image"] == "postgres:16-alpine"
    assert "orchestrator-postgres-data" in c["volumes"]


def test_orchestrator_app_depends_on_postgres_healthy():
    c = _compose()
    app = c["services"]["orchestrator-app"]
    assert app["depends_on"]["postgres"]["condition"] == "service_healthy"
