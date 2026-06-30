"""Engine config — fail-loud when enabled, inert when disabled (ADR-0005 §11)."""

from __future__ import annotations

import pytest

from delta.budget_engine.config import EngineSettings, load_settings

_KEYS = ("DELTA_BUDGET_ENGINE_ENABLED", "DELTA_ORCH_DISTRIBUTION_URL", "ORCH_SERVICE_TOKEN")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in _KEYS:
        monkeypatch.delenv(k, raising=False)


def test_enabled_by_default_requires_url_and_token(monkeypatch):
    with pytest.raises(RuntimeError, match="DELTA_ORCH_DISTRIBUTION_URL"):
        load_settings()


def test_enabled_missing_token_fails_loud(monkeypatch):
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch:8000")
    with pytest.raises(RuntimeError, match="ORCH_SERVICE_TOKEN"):
        load_settings()


def test_disabled_is_inert_no_secrets_required(monkeypatch):
    monkeypatch.setenv("DELTA_BUDGET_ENGINE_ENABLED", "0")
    settings = load_settings()
    assert settings.enabled is False
    assert settings.distribution_url == "" and settings.service_token == ""


def test_enabled_resolves_endpoint(monkeypatch):
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch:8000/")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", "tok")
    settings = load_settings()
    assert settings.enabled is True
    assert settings.distribution_endpoint() == "http://orch:8000/v1/policies/distributions"


def test_endpoint_strips_trailing_slash():
    s = EngineSettings(enabled=True, distribution_url="http://x:1///", service_token="t")
    assert s.distribution_endpoint() == "http://x:1/v1/policies/distributions"
