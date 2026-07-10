"""Unit tests for the F-031 preflight checks that need no live DB."""

from __future__ import annotations

from pathlib import Path

from preflight.checks import (
    check_config_sane,
    check_no_open_critical_high,
    check_secrets_vaulted,
)
from preflight.result import STATUS_FAIL, STATUS_PASS, STATUS_WARN

# --- secrets vaulted -------------------------------------------------------


def _reset_keyvault():
    from gateway.keyvault.settings import _reset_keyvault_settings_for_testing

    _reset_keyvault_settings_for_testing()


def test_secrets_vaulted_fails_on_env_backend(monkeypatch):
    monkeypatch.delenv("KEYVAULT_BACKEND", raising=False)
    _reset_keyvault()
    result = check_secrets_vaulted()
    assert result.status == STATUS_FAIL
    assert result.evidence["keyvault_backend"] == "env"
    _reset_keyvault()


def test_secrets_vaulted_passes_on_vault_backend(monkeypatch):
    monkeypatch.setenv("KEYVAULT_BACKEND", "vault")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.internal")
    monkeypatch.setenv("VAULT_TOKEN", "root")
    _reset_keyvault()
    result = check_secrets_vaulted()
    assert result.status == STATUS_PASS
    assert result.evidence["keyvault_backend"] == "vault"
    _reset_keyvault()


# --- open findings ---------------------------------------------------------


def _write(root: Path, rel: str, body: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_open_high_finding_fails(tmp_path):
    _write(
        tmp_path,
        "docs/followups/f-x.md",
        "# f-x\n\n**Status:** OPEN — escalated. **Severity:** High (security).\n",
    )
    result = check_no_open_critical_high(root=tmp_path)
    assert result.status == STATUS_FAIL
    assert "docs/followups/f-x.md" in result.evidence["open_findings"]


def test_open_low_finding_does_not_fail(tmp_path):
    _write(
        tmp_path,
        "docs/followups/f-low.md",
        "# f-low\n\n**Status:** OPEN. **Severity:** Low (capability gap).\n",
    )
    result = check_no_open_critical_high(root=tmp_path)
    assert result.status == STATUS_PASS


def test_closed_high_finding_does_not_fail(tmp_path):
    _write(
        tmp_path,
        "docs/audit/f-y.md",
        "# f-y\n\n**Status:** CLOSED. **Severity:** High.\n",
    )
    result = check_no_open_critical_high(root=tmp_path)
    assert result.status == STATUS_PASS


def test_open_critical_finding_fails(tmp_path):
    _write(
        tmp_path,
        "docs/audit/f-z.md",
        "# f-z\n\nStatus: OPEN\nSeverity: Critical\n",
    )
    result = check_no_open_critical_high(root=tmp_path)
    assert result.status == STATUS_FAIL


def test_no_docs_dir_warns(tmp_path):
    result = check_no_open_critical_high(root=tmp_path)
    assert result.status == STATUS_WARN


# --- config sane -----------------------------------------------------------


def _base_env(monkeypatch):
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://upstream")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/db")
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+asyncpg://fake/appdb")
    monkeypatch.setenv("SENTINEL_KEY_SECRET", "s")


def test_config_sane_fails_when_required_missing(monkeypatch):
    for v in ("UPSTREAM_BASE_URL", "DATABASE_URL", "APP_DATABASE_URL", "SENTINEL_KEY_SECRET"):
        monkeypatch.delenv(v, raising=False)
    # point pydantic at a non-existent env file so it can't pick up a real .env
    result = check_config_sane()
    assert result.status == STATUS_FAIL


def test_config_sane_warns_on_localhost_redis(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    result = check_config_sane()
    # localhost redis is flagged as a production concern (WARN, not FAIL)
    assert result.status == STATUS_WARN
    assert "redis" in result.detail.lower()
