"""Unit tests for get_relay_settings() env parsing (O-009, ADR-0009). No DB.

Covers: defaults (empty source_tokens, default allowed_paths/timeout/max_body), source-token
JSON parse + known-source-product enforcement, allowed-paths comma-split, and bad/out-of-range
overrides -> ConfigError (loud misconfig).
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_RELAY_ALLOWED_PATHS,
    DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS,
    DEFAULT_RELAY_MAX_BODY_BYTES,
    ConfigError,
    get_relay_settings,
)

_RELAY_ENV_VARS = (
    "ORCH_RELAY_SOURCE_TOKENS",
    "ORCH_RELAY_ALLOWED_PATHS",
    "ORCH_RELAY_HTTP_TIMEOUT",
    "ORCH_RELAY_MAX_BODY_BYTES",
)


@pytest.fixture
def clean_relay_env(monkeypatch):
    """Clear every relay env var so each test starts from a known-empty baseline."""
    for name in _RELAY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_relay_env):
    settings = get_relay_settings()
    assert settings.source_tokens == {}
    assert settings.allowed_paths == DEFAULT_RELAY_ALLOWED_PATHS
    assert settings.http_timeout_seconds == DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS
    assert settings.max_body_bytes == DEFAULT_RELAY_MAX_BODY_BYTES


def test_source_tokens_parsed(clean_relay_env):
    clean_relay_env.setenv(
        "ORCH_RELAY_SOURCE_TOKENS", '{"delta": "delta-tok", "rendly": "rendly-tok"}'
    )
    settings = get_relay_settings()
    assert settings.source_tokens == {"delta": "delta-tok", "rendly": "rendly-tok"}


def test_source_tokens_bad_json_raises(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_SOURCE_TOKENS", "{not json")
    with pytest.raises(ConfigError):
        get_relay_settings()


def test_source_tokens_non_object_raises(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_SOURCE_TOKENS", '["delta", "tok"]')
    with pytest.raises(ConfigError):
        get_relay_settings()


def test_source_tokens_empty_value_raises(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_SOURCE_TOKENS", '{"delta": ""}')
    with pytest.raises(ConfigError):
        get_relay_settings()


def test_source_tokens_unknown_product_raises(clean_relay_env):
    # Only "delta" and "rendly" are recognised source_products (the ecosystem data-flow
    # diagram in CLAUDE.md); anything else is a loud misconfiguration, not a silent no-op.
    clean_relay_env.setenv("ORCH_RELAY_SOURCE_TOKENS", '{"sentinel": "tok"}')
    with pytest.raises(ConfigError):
        get_relay_settings()


def test_allowed_paths_split(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_ALLOWED_PATHS", "/v1/chat/completions, /v1/models")
    settings = get_relay_settings()
    assert settings.allowed_paths == frozenset({"/v1/chat/completions", "/v1/models"})


def test_allowed_paths_missing_slash_raises(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_ALLOWED_PATHS", "v1/chat/completions")
    with pytest.raises(ConfigError):
        get_relay_settings()


def test_http_timeout_and_max_body_overrides(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_HTTP_TIMEOUT", "5.5")
    clean_relay_env.setenv("ORCH_RELAY_MAX_BODY_BYTES", "2048")
    settings = get_relay_settings()
    assert settings.http_timeout_seconds == 5.5
    assert settings.max_body_bytes == 2048


def test_max_body_bytes_below_minimum_raises(clean_relay_env):
    clean_relay_env.setenv("ORCH_RELAY_MAX_BODY_BYTES", "0")
    with pytest.raises(ConfigError):
        get_relay_settings()


def test_get_coordination_settings_embeds_relay(clean_relay_env, monkeypatch):
    # CoordinationSettings.relay is resolved the same non-fatal way as .distribution.
    monkeypatch.delenv("ORCH_ADMIN_TOKEN", raising=False)
    from orchestrator.config import RelaySettings, get_coordination_settings

    settings = get_coordination_settings()
    assert isinstance(settings.relay, RelaySettings)
    assert settings.relay.source_tokens == {}
