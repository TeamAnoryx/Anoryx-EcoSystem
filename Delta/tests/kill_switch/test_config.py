"""Kill-switch config fail-loud resolution (no DB) — pure env-var unit tests."""

from __future__ import annotations

import pytest

from delta.kill_switch.config import load_settings


def _clear(monkeypatch):
    for name in (
        "DELTA_KILL_SWITCH_ENABLED",
        "DELTA_ORCH_DISTRIBUTION_URL",
        "ORCH_SERVICE_TOKEN",
        "DELTA_KILL_SWITCH_MAX_TX_COST_CENTS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_disabled_needs_no_url_or_token(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_KILL_SWITCH_ENABLED", "0")
    settings = load_settings()
    assert settings.enabled is False
    assert settings.distribution_url == ""
    assert settings.service_token == ""


def test_enabled_by_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", "tok")
    settings = load_settings()
    assert settings.enabled is True


def test_enabled_without_url_fails_loud(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", "tok")
    with pytest.raises(RuntimeError, match="DELTA_ORCH_DISTRIBUTION_URL"):
        load_settings()


def test_enabled_without_token_fails_loud(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch")
    with pytest.raises(RuntimeError, match="ORCH_SERVICE_TOKEN"):
        load_settings()


def test_no_anomaly_ceiling_by_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", "tok")
    settings = load_settings()
    assert settings.max_single_tx_cost_cents is None


def test_anomaly_ceiling_parses_when_set(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", "tok")
    monkeypatch.setenv("DELTA_KILL_SWITCH_MAX_TX_COST_CENTS", "5000")
    settings = load_settings()
    assert settings.max_single_tx_cost_cents == 5000


def test_anomaly_ceiling_non_integer_fails_loud(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_KILL_SWITCH_ENABLED", "0")
    monkeypatch.setenv("DELTA_KILL_SWITCH_MAX_TX_COST_CENTS", "not-a-number")
    with pytest.raises(RuntimeError, match="not an integer"):
        load_settings()


def test_anomaly_ceiling_negative_fails_loud(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_KILL_SWITCH_ENABLED", "0")
    monkeypatch.setenv("DELTA_KILL_SWITCH_MAX_TX_COST_CENTS", "-1")
    with pytest.raises(RuntimeError, match="non-negative"):
        load_settings()


def test_distribution_endpoint_strips_trailing_slash(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DELTA_ORCH_DISTRIBUTION_URL", "http://orch/")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", "tok")
    settings = load_settings()
    assert settings.distribution_endpoint() == "http://orch/v1/policies/distributions"
