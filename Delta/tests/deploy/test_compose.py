"""Compose threat-model tests (D-010).

Static YAML assertions on docker-compose.yml (no Docker daemon required).
Mirrors Anoryx-AI-Orchestrator's tests/deploy/test_compose.py (O-008,
ADR-0008 Fork D), itself mirroring Anoryx-Sentinel's tests/deploy/
test_compose.py (F-010, ADR-0012 §9 vector 8): secrets are file-mounted,
never environment variables.

Delta's compose stack has TWO live app services (delta-ingest, delta-admin)
plus the existing postgres + delta-migrate services (unlike the Orchestrator's
single orchestrator-app), so the assertions below iterate both.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_DELTA_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _DELTA_ROOT / "docker-compose.yml"

_SECRET_NAMES = (
    "postgres_password",
    "delta_ingest_hmac_secret",
    "orch_service_token",
    "delta_admin_token",
)
_FORBIDDEN_ENV = (
    "POSTGRES_PASSWORD",
    "DELTA_INGEST_HMAC_SECRET",
    "ORCH_SERVICE_TOKEN",
    "DELTA_ADMIN_TOKEN",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
)
_APP_SERVICES = ("delta-ingest", "delta-admin")


def _compose() -> dict:
    return yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))


def _env_keys(service: dict) -> set[str]:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return {k.upper() for k in env}
    return {str(e).split("=", 1)[0].upper() for e in env}


def test_app_services_use_file_secrets_not_env_passwords():
    c = _compose()
    for name in _APP_SERVICES:
        svc = c["services"][name]
        env_keys = _env_keys(svc)
        for forbidden in _FORBIDDEN_ENV:
            assert forbidden not in env_keys, f"{name} env must NOT contain {forbidden}"


def test_app_services_mount_their_required_secrets():
    c = _compose()
    ingest = c["services"]["delta-ingest"]
    assert {"postgres_password", "delta_ingest_hmac_secret", "orch_service_token"}.issubset(
        set(ingest["secrets"])
    ), "delta-ingest must mount postgres_password, delta_ingest_hmac_secret, orch_service_token"

    admin = c["services"]["delta-admin"]
    assert {"postgres_password", "delta_admin_token"}.issubset(
        set(admin["secrets"])
    ), "delta-admin must mount postgres_password, delta_admin_token"


def test_top_level_secrets_are_file_based():
    c = _compose()
    secrets = c["secrets"]
    for name in _SECRET_NAMES:
        assert name in secrets, f"missing top-level secret {name}"
        assert "file" in secrets[name], f"secret {name} must be file-based"


def test_postgres_service_and_volume_present():
    c = _compose()
    assert c["services"]["postgres"]["image"] == "postgres:16-alpine"
    assert "delta-postgres-data" in c["volumes"]


def test_postgres_service_uses_password_file_not_env_value():
    # The official postgres image's own file-secret convention
    # (POSTGRES_PASSWORD_FILE), distinct from Delta's docker-entrypoint.sh
    # bridge the delta-* services use.
    c = _compose()
    pg = c["services"]["postgres"]
    env_keys = _env_keys(pg)
    assert "POSTGRES_PASSWORD" not in env_keys
    assert "POSTGRES_PASSWORD_FILE" in env_keys
    assert "postgres_password" in pg["secrets"]


def test_migrate_depends_on_postgres_healthy():
    c = _compose()
    migrate = c["services"]["delta-migrate"]
    assert migrate["depends_on"]["postgres"]["condition"] == "service_healthy"


def test_app_services_depend_on_migrate_completed():
    c = _compose()
    for name in _APP_SERVICES:
        svc = c["services"][name]
        assert (
            svc["depends_on"]["delta-migrate"]["condition"] == "service_completed_successfully"
        ), f"{name} must gate on delta-migrate completing"


def test_app_services_launch_the_correct_uvicorn_target():
    c = _compose()
    ingest_cmd = " ".join(c["services"]["delta-ingest"]["command"])
    assert "delta.ingest.app:create_app" in ingest_cmd
    assert "--factory" in ingest_cmd

    admin_cmd = " ".join(c["services"]["delta-admin"]["command"])
    assert "delta.allocation_admin.app:create_app" in admin_cmd
    assert "--factory" in admin_cmd
