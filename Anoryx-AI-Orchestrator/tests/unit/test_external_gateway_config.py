"""Unit tests for get_external_gateway_settings() env parsing (O-013, ADR-0013). No DB.

Covers: defaults (enabled=False), overrides, and bad/out-of-range overrides -> ConfigError.
UNLIKE MessagingSettings, `enabled` IS a master switch here (ADR-0013 Fork E) — this is
the Orchestrator's first surface meant for a credential outside the existing internal
trust boundary.
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT,
    DEFAULT_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE,
    DEFAULT_EXTERNAL_GATEWAY_RATE_LIMIT_PER_MINUTE,
    ConfigError,
    get_external_gateway_settings,
)

_EXTERNAL_GATEWAY_ENV_VARS = (
    "ORCH_EXTERNAL_GATEWAY_ENABLED",
    "ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE",
    "ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE",
    "ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT",
)


@pytest.fixture
def clean_external_gateway_env(monkeypatch):
    for name in _EXTERNAL_GATEWAY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_external_gateway_env):
    settings = get_external_gateway_settings()
    assert settings.enabled is False
    assert settings.default_rate_limit_per_minute == DEFAULT_EXTERNAL_GATEWAY_RATE_LIMIT_PER_MINUTE
    assert settings.max_rate_limit_per_minute == DEFAULT_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE
    assert settings.max_keys_per_tenant == DEFAULT_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT


@pytest.mark.parametrize("raw", ["1", "true", "on", "yes", "TRUE"])
def test_enabled_true_values(clean_external_gateway_env, raw):
    clean_external_gateway_env.setenv("ORCH_EXTERNAL_GATEWAY_ENABLED", raw)
    assert get_external_gateway_settings().enabled is True


@pytest.mark.parametrize("raw", ["0", "false", "", "off", "nope"])
def test_enabled_false_values(clean_external_gateway_env, raw):
    clean_external_gateway_env.setenv("ORCH_EXTERNAL_GATEWAY_ENABLED", raw)
    assert get_external_gateway_settings().enabled is False


def test_default_rate_limit_override(clean_external_gateway_env):
    clean_external_gateway_env.setenv("ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE", "10")
    assert get_external_gateway_settings().default_rate_limit_per_minute == 10


def test_max_rate_limit_override(clean_external_gateway_env):
    clean_external_gateway_env.setenv("ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE", "500")
    assert get_external_gateway_settings().max_rate_limit_per_minute == 500


def test_max_keys_per_tenant_override(clean_external_gateway_env):
    clean_external_gateway_env.setenv("ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT", "5")
    assert get_external_gateway_settings().max_keys_per_tenant == 5


@pytest.mark.parametrize(
    "name",
    [
        "ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE",
        "ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE",
        "ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT",
    ],
)
def test_non_integer_raises(clean_external_gateway_env, name):
    clean_external_gateway_env.setenv(name, "not-an-int")
    with pytest.raises(ConfigError):
        get_external_gateway_settings()


@pytest.mark.parametrize(
    "name",
    [
        "ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE",
        "ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE",
        "ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT",
    ],
)
def test_below_minimum_raises(clean_external_gateway_env, name):
    clean_external_gateway_env.setenv(name, "0")
    with pytest.raises(ConfigError):
        get_external_gateway_settings()
