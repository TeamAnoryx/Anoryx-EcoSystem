"""Unit tests for get_safety_settings() env parsing (X-004). No DB.

Covers: defaults (empty source_tokens, default max_body_bytes), source-token JSON parse +
known-source-product enforcement, and bad/out-of-range overrides -> ConfigError. Mirrors
test_identity_config.py exactly.
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_SAFETY_MAX_BODY_BYTES,
    ConfigError,
    get_safety_settings,
)

_SAFETY_ENV_VARS = ("ORCH_SAFETY_SOURCE_TOKENS", "ORCH_SAFETY_MAX_BODY_BYTES")


@pytest.fixture
def clean_safety_env(monkeypatch):
    for name in _SAFETY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_safety_env):
    settings = get_safety_settings()
    assert settings.source_tokens == {}
    assert settings.max_body_bytes == DEFAULT_SAFETY_MAX_BODY_BYTES


def test_source_tokens_parsed(clean_safety_env):
    clean_safety_env.setenv(
        "ORCH_SAFETY_SOURCE_TOKENS",
        '{"sentinel": "sen-tok", "delta": "delta-tok", "rendly": "rendly-tok"}',
    )
    settings = get_safety_settings()
    assert settings.source_tokens == {
        "sentinel": "sen-tok",
        "delta": "delta-tok",
        "rendly": "rendly-tok",
    }


def test_source_tokens_bad_json_raises(clean_safety_env):
    clean_safety_env.setenv("ORCH_SAFETY_SOURCE_TOKENS", "{not json")
    with pytest.raises(ConfigError):
        get_safety_settings()


def test_source_tokens_non_object_raises(clean_safety_env):
    clean_safety_env.setenv("ORCH_SAFETY_SOURCE_TOKENS", '["sentinel", "tok"]')
    with pytest.raises(ConfigError):
        get_safety_settings()


def test_source_tokens_empty_value_raises(clean_safety_env):
    clean_safety_env.setenv("ORCH_SAFETY_SOURCE_TOKENS", '{"sentinel": ""}')
    with pytest.raises(ConfigError):
        get_safety_settings()


def test_source_tokens_unknown_product_raises(clean_safety_env):
    clean_safety_env.setenv("ORCH_SAFETY_SOURCE_TOKENS", '{"orchestrator": "tok"}')
    with pytest.raises(ConfigError):
        get_safety_settings()


def test_max_body_bytes_override(clean_safety_env):
    clean_safety_env.setenv("ORCH_SAFETY_MAX_BODY_BYTES", "4096")
    assert get_safety_settings().max_body_bytes == 4096


def test_max_body_bytes_below_minimum_raises(clean_safety_env):
    clean_safety_env.setenv("ORCH_SAFETY_MAX_BODY_BYTES", "0")
    with pytest.raises(ConfigError):
        get_safety_settings()


def test_identity_and_safety_tokens_are_independent(clean_safety_env):
    """A distinct credential from identitySourceBearer (least privilege): configuring one
    seam's tokens does not configure the other."""
    clean_safety_env.delenv("ORCH_IDENTITY_SOURCE_TOKENS", raising=False)
    clean_safety_env.setenv("ORCH_SAFETY_SOURCE_TOKENS", '{"sentinel": "safety-only-tok"}')
    from orchestrator.config import get_identity_settings

    assert get_identity_settings().source_tokens == {}
    assert get_safety_settings().source_tokens == {"sentinel": "safety-only-tok"}
