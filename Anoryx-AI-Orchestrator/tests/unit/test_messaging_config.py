"""Unit tests for get_messaging_settings() env parsing (O-012, ADR-0012). No DB.

Covers: defaults, overrides, and bad/out-of-range overrides -> ConfigError. Unlike
AutomationSettings, there is no master enable/disable switch to test (ADR-0012 explains
why: ordinary caller-initiated CRUD, not new autonomous behavior).
"""

from __future__ import annotations

import pytest

from orchestrator.config import (
    DEFAULT_MESSAGING_MAX_BODY_BYTES,
    DEFAULT_MESSAGING_MAX_INBOX_PAGE_SIZE,
    DEFAULT_MESSAGING_MAX_STATE_VALUE_BYTES,
    ConfigError,
    get_messaging_settings,
)

_MESSAGING_ENV_VARS = (
    "ORCH_MESSAGING_MAX_BODY_BYTES",
    "ORCH_MESSAGING_MAX_STATE_VALUE_BYTES",
    "ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE",
)


@pytest.fixture
def clean_messaging_env(monkeypatch):
    for name in _MESSAGING_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_when_unset(clean_messaging_env):
    settings = get_messaging_settings()
    assert settings.max_message_body_bytes == DEFAULT_MESSAGING_MAX_BODY_BYTES
    assert settings.max_state_value_bytes == DEFAULT_MESSAGING_MAX_STATE_VALUE_BYTES
    assert settings.max_inbox_page_size == DEFAULT_MESSAGING_MAX_INBOX_PAGE_SIZE


def test_max_body_bytes_override(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_BODY_BYTES", "4096")
    assert get_messaging_settings().max_message_body_bytes == 4096


def test_max_body_bytes_below_minimum_raises(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_BODY_BYTES", "0")
    with pytest.raises(ConfigError):
        get_messaging_settings()


def test_max_body_bytes_non_integer_raises(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_BODY_BYTES", "not-a-number")
    with pytest.raises(ConfigError):
        get_messaging_settings()


def test_max_state_value_bytes_override(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_STATE_VALUE_BYTES", "8192")
    assert get_messaging_settings().max_state_value_bytes == 8192


def test_max_state_value_bytes_below_minimum_raises(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_STATE_VALUE_BYTES", "0")
    with pytest.raises(ConfigError):
        get_messaging_settings()


def test_max_inbox_page_size_override(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE", "50")
    assert get_messaging_settings().max_inbox_page_size == 50


def test_max_inbox_page_size_below_minimum_raises(clean_messaging_env):
    clean_messaging_env.setenv("ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE", "0")
    with pytest.raises(ConfigError):
        get_messaging_settings()


def test_no_master_enable_switch_exists(clean_messaging_env):
    """ADR-0012: unlike AutomationSettings.enabled, there is no master switch here — this
    is ordinary caller-initiated CRUD, not new autonomous behavior."""
    settings = get_messaging_settings()
    assert not hasattr(settings, "enabled")
