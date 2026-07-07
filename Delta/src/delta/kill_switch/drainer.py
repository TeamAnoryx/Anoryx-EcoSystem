"""Kill-switch outbox drainer — sign + publish queued kill/clear decisions.

Mirrors ``budget_engine.drainer`` exactly (same fail posture, same backoff), but claims
from the kill-switch's OWN outbox/state tables. Reuses, UNCHANGED: ``delta.policy.sign``
(the vendored ES256 signer + Delta's signing key — no new key custody surface) and
``delta.budget_engine.publisher`` (the O-004 client is generic over any signed
``budget_limit`` record; the kill-switch does not need its own copy — ADR-0006 §3.4).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from ..budget_engine.publisher import (
    PermanentPublishError,
    TransientPublishError,
    publish_signed_policy,
)
from ..ingest.errors import is_transient
from ..persistence.database import get_tenant_session
from ..policy.sign import PolicySigningKeyError, load_signing_key, sign_policy_record
from .config import KillSwitchSettings
from .outbox import (
    KillOutboxRow,
    claim_one,
    due_outbox_ids,
    mark_distributed,
    mark_failed,
    mark_retry,
)

logger = logging.getLogger("delta.kill_switch.drainer")


def _backoff_at(attempts: int, settings: KillSwitchSettings, now: datetime) -> datetime:
    delay = min(
        settings.backoff_base_seconds * (2 ** max(0, attempts - 1)),
        settings.backoff_cap_seconds,
    )
    return now + timedelta(seconds=delay)


async def drain_tenant(tenant_id: str, settings: KillSwitchSettings, now: datetime) -> None:
    """Sign + publish this tenant's due pending kill/clear decisions. Never raises."""
    try:
        key = load_signing_key()
    except PolicySigningKeyError as exc:
        logger.error(
            "delta.kill_switch signing key unavailable — kill/clear decisions remain "
            "queued and UNPUBLISHED for tenant=%s (decisions retained, NOT lost): %r",
            tenant_id,
            exc,
        )
        return

    try:
        async with get_tenant_session(tenant_id) as session:
            ids = await due_outbox_ids(session, now=now)
    except Exception as exc:  # noqa: BLE001 — the snapshot read itself failed
        _log_drain_error(exc, tenant_id)
        return

    for outbox_id in ids:
        try:
            async with get_tenant_session(tenant_id) as session:
                row = await claim_one(session, outbox_id=outbox_id, now=now)
                if row is None:
                    continue  # taken by a concurrent drainer / no longer due
                await _deliver_one(session, row, key, settings, now)
                await session.commit()
        except Exception as exc:  # noqa: BLE001 — this row's own txn; keep draining the rest
            _log_drain_error(exc, tenant_id)


def _log_drain_error(exc: Exception, tenant_id: str) -> None:
    if is_transient(exc):
        logger.warning(
            "delta.kill_switch drain deferred (outbox DB transiently unavailable; "
            "decisions retained, retried next event) tenant=%s err=%r",
            tenant_id,
            exc,
        )
    else:
        logger.error(
            "delta.kill_switch drain FAILED (non-transient — will NOT self-heal; "
            "decisions retained pending, a monitored incident) tenant=%s err=%r",
            tenant_id,
            exc,
        )


async def _deliver_one(
    session, row: KillOutboxRow, key, settings: KillSwitchSettings, now: datetime
) -> None:
    try:
        signed = sign_policy_record(row.policy_payload, key)
    except Exception as exc:  # a payload that cannot be signed is permanently bad
        await mark_failed(session, outbox_id=row.outbox_id, error=f"sign failed: {exc!r}")
        logger.error(
            "delta.kill_switch sign FAILED (dead-lettered, decision retained) policy_id=%s "
            "err=%r",
            row.policy_id,
            exc,
        )
        return

    try:
        result = await publish_signed_policy(signed, settings)
    except TransientPublishError as exc:
        attempts = row.attempts + 1
        if attempts >= settings.max_publish_attempts:
            await mark_failed(session, outbox_id=row.outbox_id, error=f"retries exhausted: {exc}")
            logger.error(
                "delta.kill_switch publish DEAD-LETTERED (retries exhausted; decision "
                "retained, NOT lost) policy_id=%s version=%d err=%r",
                row.policy_id,
                row.policy_version,
                exc,
            )
        else:
            await mark_retry(
                session,
                outbox_id=row.outbox_id,
                error=str(exc),
                next_attempt_at=_backoff_at(attempts, settings, now),
            )
            logger.warning(
                "delta.kill_switch publish transient (retry %d/%d) policy_id=%s err=%r",
                attempts,
                settings.max_publish_attempts,
                row.policy_id,
                exc,
            )
        return
    except PermanentPublishError as exc:
        await mark_failed(session, outbox_id=row.outbox_id, error=str(exc))
        logger.error(
            "delta.kill_switch publish REJECTED (dead-lettered, decision retained) "
            "policy_id=%s err=%r",
            row.policy_id,
            exc,
        )
        return

    await mark_distributed(
        session, outbox_id=row.outbox_id, distribution_id=result.distribution_id, now=now
    )
    logger.info(
        "delta.kill_switch %s policy_id=%s version=%d transition=%s distribution_id=%s",
        "KILLED" if row.transition == "kill" else "CLEARED",
        row.policy_id,
        row.policy_version,
        row.transition,
        result.distribution_id,
    )
