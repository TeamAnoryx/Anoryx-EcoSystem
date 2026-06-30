"""Outbound policy-distribution engine — drive_distribution (O-004, ADR-0004 §3.2).

Best-effort per-target fan-out (Fork C): each target is distributed independently; the
parent state aggregates HONESTLY to distributed / partial / failed (never a silent
all-or-nothing illusion). Bounded retries with exponential backoff on transient failure
(Fork D — connection error, timeout, 429, 5xx); a permanent 4xx (e.g. Sentinel rejected
the signature) short-circuits retries (retrying a rejected signature is pointless
amplification). The byte-identical signed policy record is forwarded UNCHANGED so it
verifies unchanged on Sentinel (ES256 over header.payload + scope cross-check + policy_hash)
— the Orchestrator never re-signs (Fork A) and is never the verifying authority.

EXCEPTION DISCIPLINE (ADR-0026): a DB-connectivity loss while recording one target's
bookkeeping must not abort the in-flight fan-out, so it is caught NARROWLY as
(OperationalError, InterfaceError, TimeoutError, OSError) around the per-target call ONLY.
InvalidRequestError / ProgrammingError (a double-begin or any logic defect) are deliberately
OUTSIDE that family so they RAISE rather than make the engine silently inert on a real DB.
Outbound HTTP failures are httpx-typed and handled explicitly in the retry loop, never
folded into a bare except.

SECRET HYGIENE: the bearer token, the signed policy record, and any policy field VALUE are
NEVER logged. An alert logs only distribution_id / sentinel_id / a short last_error code.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import sqlalchemy.exc

from orchestrator.config import DistributionSettings
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_distribution_audit_link,
    get_distribution,
    list_distribution_targets,
    update_distribution_state,
    update_target_state,
)

logger = logging.getLogger(__name__)

# DB-connectivity errors that must not abort an in-flight fan-out (ADR-0026): caught
# NARROWLY around the per-target call. InvalidRequestError / ProgrammingError are
# deliberately excluded so a logic defect raises rather than silently failing open.
_DB_CONNECTIVITY_ERRORS = (
    sqlalchemy.exc.OperationalError,
    sqlalchemy.exc.InterfaceError,
    sqlalchemy.exc.TimeoutError,
    OSError,
)

_HTTP_OK_FLOOR = 200
_HTTP_OK_CEIL = 300
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVER_ERROR_FLOOR = 500


async def drive_distribution(
    distribution_id: str, tenant_id: str, *, settings: DistributionSettings
) -> None:
    """Drive one distribution's outbound fan-out to all its targets (FastAPI BackgroundTask).

    Loads the distribution + targets under the tenant session (RLS-scoped, read-only), then
    distributes to each target independently (best-effort). Finally re-reads the settled
    target states, aggregates the parent state honestly, and appends a parent audit link. A
    missing distribution → no-op (nothing to do). An ordinary per-target delivery failure is
    recorded as `failed` (never raised); only an unexpected logic defect propagates.
    """
    async with get_tenant_session(tenant_id) as session:
        dist = await get_distribution(session, distribution_id)
        if dist is None:
            return
        targets = await list_distribution_targets(session, distribution_id)

    signed_record = dist["signed_record"]
    dist_meta = {
        "distribution_id": distribution_id,
        "policy_id": dist["policy_id"],
        "tenant_id": tenant_id,
        "policy_type": dist["policy_type"],
    }

    for target in targets:
        try:
            await _distribute_to_target(
                signed_record=signed_record,
                dist_meta=dist_meta,
                target=target,
                settings=settings,
            )
        except _DB_CONNECTIVITY_ERRORS:
            # A DB-connectivity loss while recording THIS target must not abort the remaining
            # fan-out (ADR-0026 narrow catch). The target stays `pending`; the parent
            # aggregates from the re-read settled states below (never a false success).
            logger.warning(
                "policy distribution target bookkeeping hit a DB connectivity error",
                extra={
                    "distribution_id": distribution_id,
                    "sentinel_id": target.get("sentinel_id"),
                },
            )

    # Re-read the settled target states and aggregate the parent state honestly.
    async with get_tenant_session(tenant_id) as session:
        settled = await list_distribution_targets(session, distribution_id)
        aggregate = _aggregate_state([t["state"] for t in settled])
        await update_distribution_state(session, distribution_id=distribution_id, state=aggregate)
        await session.commit()
    await _append_audit(dist_meta, disposition=aggregate)


def _aggregate_state(target_states: list[str]) -> str:
    """Aggregate per-target states into the parent state (Fork C, contract enum).

    all `distributed` (and at least one target) → distributed; some distributed & some not →
    partial; none distributed → failed. A distribution with zero resolved targets aggregates
    to `failed` (honest: there was nothing to distribute to).
    """
    distributed = sum(1 for state in target_states if state == "distributed")
    if distributed and distributed == len(target_states):
        return "distributed"
    if distributed:
        return "partial"
    return "failed"


async def _distribute_to_target(
    *,
    signed_record: dict[str, Any],
    dist_meta: dict[str, Any],
    target: dict[str, Any],
    settings: DistributionSettings,
) -> str:
    """Distribute to ONE target (best-effort). Returns "distributed" or "failed".

    Never raises for an ordinary delivery failure: it is recorded as `failed` (target state +
    a short last_error + alert + audit link). The signed_record is forwarded byte-identical so
    it verifies unchanged on Sentinel. httpx is imported lazily so importing this module (and
    thus constructing the app) does not require httpx for an ingest-only deployment.
    """
    import httpx

    tenant_id = dist_meta["tenant_id"]
    target_id = target["target_id"]
    sentinel_id = target["sentinel_id"]

    base_url = settings.targets.get(sentinel_id)
    if base_url is None:
        # Unknown id: nothing to distribute to (config gap). Permanent failure, no HTTP call.
        return await _fail_target(
            dist_meta=dist_meta,
            tenant_id=tenant_id,
            target_id=target_id,
            sentinel_id=sentinel_id,
            attempt_count=0,
            last_error="unknown_target",
        )
    if settings.sentinel_admin_token is None:
        # Fail-closed: we cannot authenticate to Sentinel without the outbound bearer.
        return await _fail_target(
            dist_meta=dist_meta,
            tenant_id=tenant_id,
            target_id=target_id,
            sentinel_id=sentinel_id,
            attempt_count=0,
            last_error="no_admin_token",
        )

    url = base_url.rstrip("/") + settings.intake_path
    headers = {"Authorization": f"Bearer {settings.sentinel_admin_token}"}
    last_error = "unknown_error"
    attempt = 0
    for attempt in range(1, settings.max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
                resp = await client.post(url, json=signed_record, headers=headers)
        except (httpx.TimeoutException, httpx.TransportError):
            # Connect/read timeout or a transport-layer network error → transient.
            last_error = "connect_error"
            if attempt < settings.max_attempts:
                await asyncio.sleep(settings.backoff_seconds * (2 ** (attempt - 1)))
                continue
            break
        status = resp.status_code
        if _HTTP_OK_FLOOR <= status < _HTTP_OK_CEIL:
            return await _distribute_target_success(
                dist_meta=dist_meta,
                tenant_id=tenant_id,
                target_id=target_id,
                sentinel_id=sentinel_id,
                attempt_count=attempt,
            )
        if status == _HTTP_TOO_MANY_REQUESTS or status >= _HTTP_SERVER_ERROR_FLOOR:
            # 429 / 5xx → transient: retry with exponential backoff until the ceiling.
            last_error = f"http_{status}"
            if attempt < settings.max_attempts:
                await asyncio.sleep(settings.backoff_seconds * (2 ** (attempt - 1)))
                continue
            break
        # Any other 4xx → PERMANENT reject (e.g. signature rejected): no retry.
        last_error = f"http_{status}"
        break

    return await _fail_target(
        dist_meta=dist_meta,
        tenant_id=tenant_id,
        target_id=target_id,
        sentinel_id=sentinel_id,
        attempt_count=attempt,
        last_error=last_error,
    )


async def _distribute_target_success(
    *,
    dist_meta: dict[str, Any],
    tenant_id: str,
    target_id: str,
    sentinel_id: str,
    attempt_count: int,
) -> str:
    """Record one target as `distributed` (tenant write) + a `distributed` audit link."""
    async with get_tenant_session(tenant_id) as session:
        await update_target_state(
            session,
            target_id=target_id,
            state="distributed",
            attempt_count=attempt_count,
            distributed_at=datetime.now(timezone.utc),
        )
        await session.commit()
    await _append_audit(dist_meta, disposition="distributed", sentinel_id=sentinel_id)
    return "distributed"


async def _fail_target(
    *,
    dist_meta: dict[str, Any],
    tenant_id: str,
    target_id: str,
    sentinel_id: str,
    attempt_count: int,
    last_error: str,
) -> str:
    """Record one target as `failed` (tenant write) + a `failed` audit link + an alert.

    last_error is a SHORT code (e.g. "http_500", "timeout", "connect_error", "unknown_target")
    — never policy content or PII.
    """
    async with get_tenant_session(tenant_id) as session:
        await update_target_state(
            session,
            target_id=target_id,
            state="failed",
            attempt_count=attempt_count,
            last_error=last_error,
        )
        await session.commit()
    await _append_audit(
        dist_meta, disposition="failed", sentinel_id=sentinel_id, error_reason=last_error
    )
    logger.warning(
        "policy distribution to target failed",
        extra={
            "distribution_id": dist_meta["distribution_id"],
            "sentinel_id": sentinel_id,
            "last_error": last_error,
        },
    )
    return "failed"


async def _append_audit(
    dist_meta: dict[str, Any],
    *,
    disposition: str,
    sentinel_id: str | None = None,
    error_reason: str | None = None,
) -> None:
    """Append one hash-chained distribution_audit_log link (privileged session + begin)."""
    async with get_privileged_session() as psession:
        async with psession.begin():
            await append_distribution_audit_link(
                psession,
                {
                    "distribution_id": dist_meta["distribution_id"],
                    "policy_id": dist_meta["policy_id"],
                    "tenant_id": dist_meta["tenant_id"],
                    "policy_type": dist_meta["policy_type"],
                },
                disposition=disposition,
                sentinel_id=sentinel_id,
                error_reason=error_reason,
            )
