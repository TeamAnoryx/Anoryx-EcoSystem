"""Unit tests for get_automation_settings() env parsing (O-011, ADR-0011). No DB.

Covers: defaults (enabled=False, max_rules_per_tenant=20), ORCH_AUTOMATION_ENABLED
truthy-value parsing, ORCH_AUTOMATION_MAX_RULES_PER_TENANT overrides, and an
out-of-range/invalid override -> ConfigError (loud misconfiguration).
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_AUTOMATION_MAX_RULES_PER_TENANT,
    ConfigError,
    get_automation_settings,
)

_AUTOMATION_ENV_VARS = ("ORCH_AUTOMATION_ENABLED", "ORCH_AUTOMATION_MAX_RULES_PER_TENANT")


@pytest.fixture
def clean_automation_env(monkeypatch):
    for name in _AUTOMATION_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_automation_env):
    settings = get_automation_settings()
    assert settings.enabled is False
    assert settings.max_rules_per_tenant == DEFAULT_AUTOMATION_MAX_RULES_PER_TENANT


@pytest.mark.parametrize("value", ["1", "true", "True", "on", "yes"])
def test_enabled_truthy_values(clean_automation_env, value):
    clean_automation_env.setenv("ORCH_AUTOMATION_ENABLED", value)
    assert get_automation_settings().enabled is True


@pytest.mark.parametrize("value", ["0", "false", "off", "no", ""])
def test_enabled_falsy_values(clean_automation_env, value):
    clean_automation_env.setenv("ORCH_AUTOMATION_ENABLED", value)
    assert get_automation_settings().enabled is False


def test_max_rules_per_tenant_override(clean_automation_env):
    clean_automation_env.setenv("ORCH_AUTOMATION_MAX_RULES_PER_TENANT", "5")
    assert get_automation_settings().max_rules_per_tenant == 5


def test_max_rules_per_tenant_non_integer_raises(clean_automation_env):
    clean_automation_env.setenv("ORCH_AUTOMATION_MAX_RULES_PER_TENANT", "not-a-number")
    with pytest.raises(ConfigError):
        get_automation_settings()


def test_max_rules_per_tenant_below_minimum_raises(clean_automation_env):
    clean_automation_env.setenv("ORCH_AUTOMATION_MAX_RULES_PER_TENANT", "0")
    with pytest.raises(ConfigError):
        get_automation_settings()
