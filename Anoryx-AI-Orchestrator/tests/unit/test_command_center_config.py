"""Unit tests for get_command_center_settings() env parsing (O-014, ADR-0014). No DB.

Covers: defaults, overrides, and bad/out-of-range overrides -> ConfigError. No master
enable/disable switch to test (ADR-0014 Fork F explains why: read-only summary + an
already-explicit operator-triggered action, not new autonomous behavior).
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_COMMAND_CENTER_LOOKBACK_HOURS,
    ConfigError,
    get_command_center_settings,
)

_ENV_VAR = "ORCH_COMMAND_CENTER_LOOKBACK_HOURS"


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv(_ENV_VAR, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_env):
    settings = get_command_center_settings()
    assert settings.lookback_hours == DEFAULT_COMMAND_CENTER_LOOKBACK_HOURS


def test_override(clean_env):
    clean_env.setenv(_ENV_VAR, "6")
    assert get_command_center_settings().lookback_hours == 6


def test_non_integer_raises(clean_env):
    clean_env.setenv(_ENV_VAR, "not-an-int")
    with pytest.raises(ConfigError):
        get_command_center_settings()


def test_below_minimum_raises(clean_env):
    clean_env.setenv(_ENV_VAR, "0")
    with pytest.raises(ConfigError):
        get_command_center_settings()
