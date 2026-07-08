"""Coordinated-push target selection + staleness logic (O-005, ADR-0005, Fork B1).

Pure unit tests over coordinator._select_targets and health.effective_health_status: a target
is selected iff enabled AND effective-healthy AND capable AND its endpoint validates; every
exclusion is surfaced with an honest reason. Endpoints use IP literals so validation is
deterministic and offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from orchestrator.config import CoordinationSettings, DistributionSettings, RelaySettings
from orchestrator.coordination.coordinator import _select_targets
from orchestrator.coordination.health import effective_health_status

_NOW = datetime(2026, 6, 30, 12, 0, 0, tzinfo=timezone.utc)
# Marker so the _sentinel default is a FRESH timestamp (relative to the real datetime.now()
# that _select_targets uses internally), distinct from an explicit None ("never checked").
_FRESH = object()


def _settings(
    *, allowlist: frozenset[str] = frozenset(), staleness: int = 300
) -> CoordinationSettings:
    return CoordinationSettings(
        admin_token="op-token",  # noqa: S106 - test fake
        endpoint_allowlist=allowlist,
        allow_http=False,
        health_path="/healthz",
        health_timeout_seconds=5.0,
        staleness_seconds=staleness,
        unreachable_threshold=3,
        distribution=DistributionSettings(
            service_token=None,
            sentinel_admin_token="adm",  # noqa: S106 - test fake
            targets={},
            intake_path="/admin/policies/intake",
            max_attempts=2,
            backoff_seconds=0.0,
            http_timeout_seconds=5.0,
        ),
        relay=RelaySettings(
            source_tokens={},
            allowed_paths=frozenset({"/v1/chat/completions"}),
            http_timeout_seconds=5.0,
            max_body_bytes=1_048_576,
        ),
    )


def _sentinel(
    sentinel_id: str,
    *,
    endpoint: str = "https://8.8.8.8",
    capabilities: list[str] | None = None,
    health_status: str = "healthy",
    enabled: bool = True,
    last_checked_at: object = _FRESH,
) -> dict:
    # _FRESH → a real now() so a "healthy" sentinel is not treated as stale by _select_targets
    # (which uses the real wall clock). An explicit None means "never checked".
    checked = datetime.now(timezone.utc) if last_checked_at is _FRESH else last_checked_at
    return {
        "sentinel_id": sentinel_id,
        "endpoint": endpoint,
        "capabilities": capabilities if capabilities is not None else ["model_allowlist"],
        "health_status": health_status,
        "enabled": enabled,
        "consecutive_failures": 0,
        "last_checked_at": checked,
    }


# --------------------------------------------------------------------------- #
# _select_targets
# --------------------------------------------------------------------------- #


def test_selects_healthy_capable_valid() -> None:
    sentinels = [_sentinel("s-a")]
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings()
    )
    assert selected == {"s-a": "https://8.8.8.8"}
    assert skipped == []


def test_skips_disabled() -> None:
    sentinels = [_sentinel("s-a", enabled=False)]
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings()
    )
    assert selected == {}
    assert skipped == [{"sentinel_id": "s-a", "reason": "disabled"}]


def test_skips_unhealthy() -> None:
    sentinels = [_sentinel("s-a", health_status="unreachable")]
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings()
    )
    assert selected == {}
    assert skipped == [{"sentinel_id": "s-a", "reason": "unhealthy"}]


def test_skips_stale_healthy_as_unhealthy() -> None:
    stale = _NOW - timedelta(seconds=10_000)
    sentinels = [_sentinel("s-a", last_checked_at=stale)]
    # The pure helper uses datetime.now(); a 10000s-old check is well past any staleness window.
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings(staleness=300)
    )
    assert selected == {}
    assert skipped == [{"sentinel_id": "s-a", "reason": "unhealthy"}]


def test_skips_incapable() -> None:
    sentinels = [_sentinel("s-a", capabilities=["budget_limit"])]
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings()
    )
    assert selected == {}
    assert skipped == [{"sentinel_id": "s-a", "reason": "incapable"}]


def test_skips_invalid_endpoint() -> None:
    # A private IP endpoint that is not allowlisted no longer validates → skipped.
    sentinels = [_sentinel("s-a", endpoint="https://10.0.0.9")]
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings()
    )
    assert selected == {}
    assert skipped == [{"sentinel_id": "s-a", "reason": "invalid_endpoint"}]


def test_mixed_fleet_partitions_correctly() -> None:
    sentinels = [
        _sentinel("s-ok"),
        _sentinel("s-incap", capabilities=["data_lock"]),
        _sentinel("s-down", health_status="unreachable"),
        _sentinel("s-off", enabled=False),
    ]
    selected, skipped = _select_targets(
        sentinels, policy_type="model_allowlist", settings=_settings()
    )
    assert selected == {"s-ok": "https://8.8.8.8"}
    reasons = {s["sentinel_id"]: s["reason"] for s in skipped}
    assert reasons == {"s-incap": "incapable", "s-down": "unhealthy", "s-off": "disabled"}


# --------------------------------------------------------------------------- #
# effective_health_status (staleness)
# --------------------------------------------------------------------------- #


def test_effective_healthy_fresh_stays_healthy() -> None:
    s = _sentinel("s", last_checked_at=_NOW)
    assert effective_health_status(s, staleness_seconds=300, now=_NOW) == "healthy"


def test_effective_healthy_stale_becomes_degraded() -> None:
    s = _sentinel("s", last_checked_at=_NOW - timedelta(seconds=400))
    assert effective_health_status(s, staleness_seconds=300, now=_NOW) == "degraded"


def test_effective_healthy_never_checked_becomes_degraded() -> None:
    s = _sentinel("s", last_checked_at=None)
    assert effective_health_status(s, staleness_seconds=300, now=_NOW) == "degraded"


def test_effective_staleness_disabled_keeps_healthy() -> None:
    s = _sentinel("s", last_checked_at=_NOW - timedelta(days=30))
    assert effective_health_status(s, staleness_seconds=0, now=_NOW) == "healthy"


def test_effective_non_healthy_passthrough() -> None:
    s = _sentinel("s", health_status="unreachable", last_checked_at=None)
    assert effective_health_status(s, staleness_seconds=300, now=_NOW) == "unreachable"
