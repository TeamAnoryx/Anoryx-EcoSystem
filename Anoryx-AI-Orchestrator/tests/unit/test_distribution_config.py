"""Unit tests for get_distribution_settings() env parsing (O-004, ADR-0004). No DB.

Covers: token absence → None (non-fatal), token presence, targets JSON parse, bad/non-object
targets → ConfigError (loud misconfig), default intake_path / attempts / backoff / timeout, and
bad/out-of-range numeric bounds → ConfigError.
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_DISTRIBUTION_BACKOFF_SECONDS,
    DEFAULT_DISTRIBUTION_HTTP_TIMEOUT_SECONDS,
    DEFAULT_DISTRIBUTION_MAX_ATTEMPTS,
    DEFAULT_SENTINEL_INTAKE_PATH,
    ConfigError,
    get_distribution_settings,
)

_DIST_ENV_VARS = (
    "ORCH_SERVICE_TOKEN",
    "SENTINEL_ADMIN_TOKEN",
    "ORCH_DISTRIBUTION_TARGETS",
    "ORCH_SENTINEL_INTAKE_PATH",
    "ORCH_DISTRIBUTION_MAX_ATTEMPTS",
    "ORCH_DISTRIBUTION_BACKOFF_SECONDS",
    "ORCH_DISTRIBUTION_HTTP_TIMEOUT",
)


@pytest.fixture
def clean_dist_env(monkeypatch):
    """Clear every distribution env var so each test starts from a known-empty baseline."""
    for name in _DIST_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_dist_env):
    settings = get_distribution_settings()
    assert settings.service_token is None
    assert settings.sentinel_admin_token is None
    assert settings.targets == {}
    assert settings.intake_path == DEFAULT_SENTINEL_INTAKE_PATH
    assert settings.max_attempts == DEFAULT_DISTRIBUTION_MAX_ATTEMPTS
    assert settings.backoff_seconds == DEFAULT_DISTRIBUTION_BACKOFF_SECONDS
    assert settings.http_timeout_seconds == DEFAULT_DISTRIBUTION_HTTP_TIMEOUT_SECONDS


def test_tokens_and_targets_parsed(clean_dist_env):
    clean_dist_env.setenv("ORCH_SERVICE_TOKEN", "svc")
    clean_dist_env.setenv("SENTINEL_ADMIN_TOKEN", "adm")
    clean_dist_env.setenv(
        "ORCH_DISTRIBUTION_TARGETS", '{"s1": "https://a.example", "s2": "https://b.example"}'
    )
    settings = get_distribution_settings()
    assert settings.service_token == "svc"  # noqa: S105 - test-only fake
    assert settings.sentinel_admin_token == "adm"  # noqa: S105 - test-only fake
    assert settings.targets == {"s1": "https://a.example", "s2": "https://b.example"}


def test_empty_token_is_none(clean_dist_env):
    clean_dist_env.setenv("ORCH_SERVICE_TOKEN", "")
    assert get_distribution_settings().service_token is None


def test_intake_path_and_bounds_overrides(clean_dist_env):
    clean_dist_env.setenv("ORCH_SENTINEL_INTAKE_PATH", "/custom/intake")
    clean_dist_env.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "5")
    clean_dist_env.setenv("ORCH_DISTRIBUTION_BACKOFF_SECONDS", "1.5")
    clean_dist_env.setenv("ORCH_DISTRIBUTION_HTTP_TIMEOUT", "20")
    settings = get_distribution_settings()
    assert settings.intake_path == "/custom/intake"
    assert settings.max_attempts == 5
    assert settings.backoff_seconds == 1.5
    assert settings.http_timeout_seconds == 20.0


def test_targets_bad_json_raises(clean_dist_env):
    clean_dist_env.setenv("ORCH_DISTRIBUTION_TARGETS", "{not json")
    with pytest.raises(ConfigError):
        get_distribution_settings()


def test_targets_non_object_raises(clean_dist_env):
    clean_dist_env.setenv("ORCH_DISTRIBUTION_TARGETS", '["s1", "https://a"]')
    with pytest.raises(ConfigError):
        get_distribution_settings()


def test_targets_non_string_value_raises(clean_dist_env):
    clean_dist_env.setenv("ORCH_DISTRIBUTION_TARGETS", '{"s1": 123}')
    with pytest.raises(ConfigError):
        get_distribution_settings()


def test_max_attempts_non_integer_raises(clean_dist_env):
    clean_dist_env.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "abc")
    with pytest.raises(ConfigError):
        get_distribution_settings()


def test_max_attempts_below_minimum_raises(clean_dist_env):
    clean_dist_env.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "0")
    with pytest.raises(ConfigError):
        get_distribution_settings()


def test_backoff_negative_raises(clean_dist_env):
    clean_dist_env.setenv("ORCH_DISTRIBUTION_BACKOFF_SECONDS", "-1")
    with pytest.raises(ConfigError):
        get_distribution_settings()
