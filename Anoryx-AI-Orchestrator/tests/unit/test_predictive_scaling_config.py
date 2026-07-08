"""Unit tests for get_predictive_scaling_settings() env parsing (O-015, ADR-0015). No DB.

Covers: defaults, overrides, and bad/out-of-range overrides -> ConfigError. No master
enable/disable switch to test (ADR-0015 Fork G: a pure read, no autonomous behavior to
gate).
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_PREDICTIVE_SCALING_HORIZON_HOURS,
    DEFAULT_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD,
    DEFAULT_PREDICTIVE_SCALING_WINDOW_HOURS,
    ConfigError,
    get_predictive_scaling_settings,
)

_ENV_VARS = (
    "ORCH_PREDICTIVE_SCALING_WINDOW_HOURS",
    "ORCH_PREDICTIVE_SCALING_HORIZON_HOURS",
    "ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD",
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_env):
    settings = get_predictive_scaling_settings()
    assert settings.window_hours == DEFAULT_PREDICTIVE_SCALING_WINDOW_HOURS
    assert settings.horizon_hours == DEFAULT_PREDICTIVE_SCALING_HORIZON_HOURS
    assert settings.spike_ratio_threshold == DEFAULT_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD


def test_window_hours_override(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_WINDOW_HOURS", "6")
    assert get_predictive_scaling_settings().window_hours == 6


def test_horizon_hours_override(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_HORIZON_HOURS", "72")
    assert get_predictive_scaling_settings().horizon_hours == 72


def test_spike_ratio_threshold_override(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD", "3.5")
    assert get_predictive_scaling_settings().spike_ratio_threshold == 3.5


def test_window_hours_below_minimum_raises(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_WINDOW_HOURS", "0")
    with pytest.raises(ConfigError):
        get_predictive_scaling_settings()


def test_horizon_hours_non_integer_raises(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_HORIZON_HOURS", "nope")
    with pytest.raises(ConfigError):
        get_predictive_scaling_settings()


def test_spike_ratio_threshold_below_minimum_raises(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD", "0.5")
    with pytest.raises(ConfigError):
        get_predictive_scaling_settings()


def test_spike_ratio_threshold_non_numeric_raises(clean_env):
    clean_env.setenv("ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD", "not-a-number")
    with pytest.raises(ConfigError):
        get_predictive_scaling_settings()
