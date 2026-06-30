"""Health-check subsystem (O-005, ADR-0005, Fork A1).

`run_health_cycle()` polls every ENABLED registered Sentinel, re-validates its endpoint through
the SSRF gate (never probe an unvalidated endpoint), probes the documented health path, and
persists a `healthy / degraded / unreachable` transition with consecutive-failure bookkeeping.
It is exposed as a plain awaitable (driven by a scheduler in production; awaited directly in the
coordination e2e for deterministic real transitions — mirrors how O-004's `drive_distribution`
is a BackgroundTask in prod but awaited in tests).

HONESTY BOUNDARY (E1): "healthy" means the endpoint answered a reachability probe per the
documented contract (the O-004 shim stand-in) — it is NOT verified-enforcing. The real Sentinel
health route is a separate Sentinel task.

`effective_health_status()` applies the staleness rule at SELECTION time: a `healthy` target
whose last check is older than the staleness window is treated as `degraded` (stale), so a
never-re-checked target is never trusted as healthy indefinitely.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from orchestrator.config import CoordinationSettings
from orchestrator.coordination.endpoint_validation import (
    EndpointValidationError,
    validate_endpoint,
)
from orchestrator.coordination.registry import fetch_sentinels
from orchestrator.persistence import repositories as repo
from orchestrator.persistence.database import get_privileged_session

logger = logging.getLogger(__name__)

_HTTP_OK_FLOOR = 200
_HTTP_OK_CEIL = 300

_HEALTHY = "healthy"
_DEGRADED = "degraded"
_UNREACHABLE = "unreachable"


def effective_health_status(
    sentinel: dict[str, Any], *, staleness_seconds: int, now: datetime
) -> str:
    """Return the sentinel's health status, demoting a STALE `healthy` to `degraded`.

    A `healthy` target whose last_checked_at is missing or older than staleness_seconds is
    treated as `degraded` so the coordinated push (healthy-only) never trusts stale health.
    staleness_seconds <= 0 disables the rule.
    """
    status = sentinel.get("health_status")
    if status != _HEALTHY or staleness_seconds <= 0:
        return status if isinstance(status, str) else "unknown"
    last_checked = sentinel.get("last_checked_at")
    if last_checked is None:
        return _DEGRADED
    if (now - last_checked).total_seconds() > staleness_seconds:
        return _DEGRADED
    return status


async def _probe_one(
    sentinel: dict[str, Any], *, settings: CoordinationSettings
) -> tuple[str, int, datetime | None, str | None]:
    """Probe ONE sentinel. Returns (status, consecutive_failures, last_healthy_at, reason).

    Re-validates the endpoint first (SSRF): an endpoint that no longer validates is `unreachable`
    (never probed). A 2xx → healthy (failures reset to 0). A reachable non-2xx → degraded. A
    connection error / timeout / DNS failure → degraded, escalating to unreachable at the
    configured consecutive-failure threshold. Never raises for an ordinary probe failure.
    """
    import httpx

    prior_failures = int(sentinel.get("consecutive_failures") or 0)
    endpoint = sentinel["endpoint"]

    try:
        validated = validate_endpoint(
            endpoint, allowlist=settings.endpoint_allowlist, allow_http=settings.allow_http
        )
    except EndpointValidationError as exc:
        # An endpoint that no longer validates must never receive an outbound call.
        return (_UNREACHABLE, prior_failures + 1, None, f"invalid_endpoint:{exc.reason}")

    url = validated.rstrip("/") + settings.health_path
    try:
        async with httpx.AsyncClient(timeout=settings.health_timeout_seconds) as client:
            resp = await client.get(url)
    except (httpx.TimeoutException, httpx.TransportError):
        failures = prior_failures + 1
        status = _UNREACHABLE if failures >= settings.unreachable_threshold else _DEGRADED
        return (status, failures, None, "connect_error")

    if _HTTP_OK_FLOOR <= resp.status_code < _HTTP_OK_CEIL:
        return (_HEALTHY, 0, datetime.now(timezone.utc), None)
    # Reachable but not 2xx → degraded (the host answered, but not with a healthy signal).
    return (_DEGRADED, prior_failures + 1, None, f"http_{resp.status_code}")


async def run_health_cycle(*, settings: CoordinationSettings) -> list[dict[str, Any]]:
    """Poll every enabled Sentinel, persist transitions, return per-sentinel results.

    Each result: {sentinel_id, previous_status, status, consecutive_failures, reason?}. Disabled
    sentinels are skipped (not probed). Each transition is persisted in its own privileged
    transaction so a single probe failure cannot abort the cycle.
    """
    sentinels = await fetch_sentinels()
    results: list[dict[str, Any]] = []
    for sentinel in sentinels:
        sentinel_id = sentinel["sentinel_id"]
        previous = sentinel.get("health_status")
        if not sentinel.get("enabled", True):
            results.append(
                {
                    "sentinel_id": sentinel_id,
                    "previous_status": previous,
                    "status": previous,
                    "consecutive_failures": int(sentinel.get("consecutive_failures") or 0),
                    "reason": "disabled",
                }
            )
            continue
        status, failures, last_healthy_at, reason = await _probe_one(sentinel, settings=settings)
        checked_at = datetime.now(timezone.utc)
        async with get_privileged_session() as psession:
            async with psession.begin():
                await repo.update_sentinel_health(
                    psession,
                    sentinel_id=sentinel_id,
                    health_status=status,
                    consecutive_failures=failures,
                    last_checked_at=checked_at,
                    last_healthy_at=last_healthy_at,
                )
        result: dict[str, Any] = {
            "sentinel_id": sentinel_id,
            "previous_status": previous,
            "status": status,
            "consecutive_failures": failures,
        }
        if reason is not None:
            result["reason"] = reason
        results.append(result)
    return results
