"""get_coordination_settings env resolution (O-005, ADR-0005). No DB.

Covers the env → CoordinationSettings path (the e2e drives a hand-built settings fixture, so this
is where the parsing/normalisation is exercised): allowlist split + lowercasing, allow_http
flag, health-path leading-slash normalisation, bounded ints, and the embedded distribution.
"""

from __future__ import annotations

import pytest

from orchestrator.config import DistributionSettings, get_coordination_settings

_VARS = (
    "ORCH_ADMIN_TOKEN",
    "ORCH_REGISTRY_ENDPOINT_ALLOWLIST",
    "ORCH_REGISTRY_ALLOW_HTTP",
    "ORCH_SENTINEL_HEALTH_PATH",
    "ORCH_HEALTH_HTTP_TIMEOUT",
    "ORCH_HEALTH_STALENESS_SECONDS",
    "ORCH_HEALTH_UNREACHABLE_THRESHOLD",
    "ORCH_AUTO_ROLLBACK_ENABLED",
)


@pytest.fixture
def clean_env(monkeypatch):
    for var in (*_VARS, "ORCH_DISTRIBUTION_TARGETS", "ORCH_SERVICE_TOKEN", "SENTINEL_ADMIN_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_defaults_are_fail_closed(clean_env) -> None:
    s = get_coordination_settings()
    assert s.admin_token is None  # fail-closed (the boundary enforces presence)
    assert s.endpoint_allowlist == frozenset()  # empty → only public https passes
    assert s.allow_http is False
    assert s.health_path == "/healthz"
    assert s.health_timeout_seconds == 10.0
    assert s.staleness_seconds == 300
    assert s.unreachable_threshold == 3
    assert isinstance(s.distribution, DistributionSettings)
    assert s.auto_rollback_enabled is False  # O-014: new autonomous behavior defaults OFF


def test_allowlist_is_split_and_lowercased(clean_env) -> None:
    clean_env.setenv(
        "ORCH_REGISTRY_ENDPOINT_ALLOWLIST", "127.0.0.1, Example.COM:8443 , ,sentinel.local"
    )
    s = get_coordination_settings()
    assert s.endpoint_allowlist == frozenset({"127.0.0.1", "example.com:8443", "sentinel.local"})


def test_allow_http_flag(clean_env) -> None:
    clean_env.setenv("ORCH_REGISTRY_ALLOW_HTTP", "1")
    assert get_coordination_settings().allow_http is True
    clean_env.setenv("ORCH_REGISTRY_ALLOW_HTTP", "no")
    assert get_coordination_settings().allow_http is False


def test_health_path_leading_slash_normalised(clean_env) -> None:
    clean_env.setenv("ORCH_SENTINEL_HEALTH_PATH", "readyz")
    assert get_coordination_settings().health_path == "/readyz"


def test_bounded_overrides(clean_env) -> None:
    clean_env.setenv("ORCH_HEALTH_STALENESS_SECONDS", "60")
    clean_env.setenv("ORCH_HEALTH_UNREACHABLE_THRESHOLD", "2")
    clean_env.setenv("ORCH_HEALTH_HTTP_TIMEOUT", "3.5")
    clean_env.setenv("ORCH_ADMIN_TOKEN", "op-secret")
    s = get_coordination_settings()
    assert s.staleness_seconds == 60
    assert s.unreachable_threshold == 2
    assert s.health_timeout_seconds == 3.5
    assert s.admin_token == "op-secret"  # noqa: S105 - test fake


def test_unreachable_threshold_below_minimum_raises(clean_env) -> None:
    from orchestrator.config import ConfigError

    clean_env.setenv("ORCH_HEALTH_UNREACHABLE_THRESHOLD", "0")
    with pytest.raises(ConfigError):
        get_coordination_settings()


def test_auto_rollback_enabled_flag(clean_env) -> None:
    clean_env.setenv("ORCH_AUTO_ROLLBACK_ENABLED", "1")
    assert get_coordination_settings().auto_rollback_enabled is True
    clean_env.setenv("ORCH_AUTO_ROLLBACK_ENABLED", "false")
    assert get_coordination_settings().auto_rollback_enabled is False
