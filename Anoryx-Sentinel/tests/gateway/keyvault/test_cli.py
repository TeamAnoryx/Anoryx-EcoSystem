"""sentinel-keyvault CLI tests (F-027) — env backend only (no live Vault/AWS
needed); verifies the CLI never prints credential values."""

from __future__ import annotations

import pytest

from gateway.config import _reset_settings
from gateway.keyvault import cli as keyvault_cli
from gateway.keyvault.settings import _reset_keyvault_settings_for_testing

_BASE_KWARGS = {
    "upstream_base_url": "http://fake-upstream",
    "database_url": "postgresql+asyncpg://fake/db",
    "app_database_url": "postgresql+asyncpg://fake/appdb",
    "sentinel_key_secret": "test-secret",
}


@pytest.fixture(autouse=True)
def _reset_caches(monkeypatch):
    for var in (
        "ANTHROPIC_API_KEY",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "KEYVAULT_BACKEND",
        "UPSTREAM_BASE_URL",
        "DATABASE_URL",
        "APP_DATABASE_URL",
        "SENTINEL_KEY_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    for k, v in _BASE_KWARGS.items():
        monkeypatch.setenv(k.upper(), v)
    _reset_settings()
    _reset_keyvault_settings_for_testing()
    yield
    _reset_settings()
    _reset_keyvault_settings_for_testing()


def test_status_reports_not_configured_when_no_secrets(capsys):
    exit_code = keyvault_cli.main(["status"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "backend: env" in out
    assert "anthropic: not configured" in out
    assert "bedrock: not configured" in out


def test_status_reports_ok_when_anthropic_key_set(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-value-should-not-print")
    _reset_settings()
    exit_code = keyvault_cli.main(["status"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "anthropic: ok" in out
    assert "sk-ant-real-value-should-not-print" not in out


def test_verify_succeeds_for_configured_provider(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret-value")
    _reset_settings()
    exit_code = keyvault_cli.main(["verify", "--provider", "anthropic"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ok:" in out
    assert "sk-ant-secret-value" not in out


def test_verify_fails_for_unconfigured_provider(capsys):
    exit_code = keyvault_cli.main(["verify", "--provider", "bedrock"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "not configured" in err


def test_verify_rejects_unknown_provider_choice():
    with pytest.raises(SystemExit):
        keyvault_cli.main(["verify", "--provider", "openai-unsupported"])
