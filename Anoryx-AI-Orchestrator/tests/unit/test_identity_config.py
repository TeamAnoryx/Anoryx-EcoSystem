"""Unit tests for get_identity_settings() env parsing (O-010, ADR-0010). No DB.

Covers: defaults (empty source_tokens, default max_body_bytes), source-token JSON parse +
known-source-product enforcement, and bad/out-of-range overrides -> ConfigError.
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_IDENTITY_MAX_BODY_BYTES,
    ConfigError,
    get_identity_settings,
)

_IDENTITY_ENV_VARS = ("ORCH_IDENTITY_SOURCE_TOKENS", "ORCH_IDENTITY_MAX_BODY_BYTES")


@pytest.fixture
def clean_identity_env(monkeypatch):
    for name in _IDENTITY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_identity_env):
    settings = get_identity_settings()
    assert settings.source_tokens == {}
    assert settings.max_body_bytes == DEFAULT_IDENTITY_MAX_BODY_BYTES


def test_source_tokens_parsed(clean_identity_env):
    clean_identity_env.setenv(
        "ORCH_IDENTITY_SOURCE_TOKENS",
        '{"sentinel": "sen-tok", "delta": "delta-tok", "rendly": "rendly-tok"}',
    )
    settings = get_identity_settings()
    assert settings.source_tokens == {
        "sentinel": "sen-tok",
        "delta": "delta-tok",
        "rendly": "rendly-tok",
    }


def test_source_tokens_bad_json_raises(clean_identity_env):
    clean_identity_env.setenv("ORCH_IDENTITY_SOURCE_TOKENS", "{not json")
    with pytest.raises(ConfigError):
        get_identity_settings()


def test_source_tokens_non_object_raises(clean_identity_env):
    clean_identity_env.setenv("ORCH_IDENTITY_SOURCE_TOKENS", '["sentinel", "tok"]')
    with pytest.raises(ConfigError):
        get_identity_settings()


def test_source_tokens_empty_value_raises(clean_identity_env):
    clean_identity_env.setenv("ORCH_IDENTITY_SOURCE_TOKENS", '{"sentinel": ""}')
    with pytest.raises(ConfigError):
        get_identity_settings()


def test_source_tokens_unknown_product_raises(clean_identity_env):
    clean_identity_env.setenv("ORCH_IDENTITY_SOURCE_TOKENS", '{"orchestrator": "tok"}')
    with pytest.raises(ConfigError):
        get_identity_settings()


def test_max_body_bytes_override(clean_identity_env):
    clean_identity_env.setenv("ORCH_IDENTITY_MAX_BODY_BYTES", "4096")
    assert get_identity_settings().max_body_bytes == 4096


def test_max_body_bytes_below_minimum_raises(clean_identity_env):
    clean_identity_env.setenv("ORCH_IDENTITY_MAX_BODY_BYTES", "0")
    with pytest.raises(ConfigError):
        get_identity_settings()
