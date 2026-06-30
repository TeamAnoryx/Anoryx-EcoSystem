"""Outbox drainer — sign + publish queued enforcement decisions (ADR-0005 §3.4/§3.5).

Claims due ``pending`` outbox rows (FOR UPDATE SKIP LOCKED), signs each payload fresh with
Delta's key, and POSTs it to the real O-004 seam. Delivery outcomes:

  * 202              -> ``distributed`` (record the distribution_id).
  * transient (429/5xx/connection) -> ``mark_retry`` with bounded backoff; on the
    ``max_publish_attempts`` retry it is dead-lettered (``failed``) WITH AN ALERT — the
    row is retained, never dropped (vector 11).
  * permanent 4xx    -> ``failed`` (dead-letter) + alert.

A momentarily-missing signing key leaves EVERY row pending (no publish) + a loud alert —
never fail-open, never a silent drop (vector 11). The drain is best-effort inline (after
the eval commit, for sub-second latency) and also serves as the event-driven retry sweep:
each event re-drains its tenant's due rows, respecting each row's backoff.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from ..ingest.errors import is_transient
from ..persistence.database import get_tenant_session
from ..policy.sign import PolicySigningKeyError, load_signing_key, sign_policy_record
from .config import EngineSettings
from .outbox import OutboxRow, claim_one, due_outbox_ids, mark_distributed, mark_failed, mark_retry
from .publisher import PermanentPublishError, TransientPublishError, publish_signed_policy

logger = logging.getLogger("delta.budget_engine.drainer")


def _backoff_at(attempts: int, settings: EngineSettings, now: datetime) -> datetime:
    delay = min(
        settings.backoff_base_seconds * (2 ** max(0, attempts - 1)),
        settings.backoff_cap_seconds,
    )
    return now + timedelta(seconds=delay)


async def drain_tenant(tenant_id: str, settings: EngineSettings, now: datetime) -> None:
    """Sign + publish this tenant's due pending decisions. Never raises to the caller."""
    try:
        key = load_signing_key()
    except PolicySigningKeyError as exc:
        # Config error: decisions stay queued (NOT lost), nothing is published, alert loud.
        # This is a publish failure, NOT fail-open and NOT a silent drop (ADR-0005 §3.5).
        logger.error(
            "delta.budget signing key unavailable — %d-or-more enforcement decisions remain "
            "queued and UNPUBLISHED for tenant=%s (decisions retained, NOT lost): %r",
            1,
            tenant_id,
            exc,
        )
        return

    # Snapshot the due ids (read-only), then deliver each in its OWN transaction so a commit
    # failure on one row never rolls back already-recorded deliveries of the others.
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
    """Classify a drain failure. Decisions are never lost (they stay pending) either way.

    A persistent non-transient bug (schema/programming error) is escalated as ERROR rather
    than mislabelled as a connectivity blip and retried forever (the F-007-FU lesson).
    """
    if is_transient(exc):
        logger.warning(
            "delta.budget drain deferred (outbox DB transiently unavailable; decisions "
            "retained, retried next event) tenant=%s err=%r",
            tenant_id,
            exc,
        )
    else:
        logger.error(
            "delta.budget drain FAILED (non-transient — will NOT self-heal; decisions "
            "retained pending, a monitored incident) tenant=%s err=%r",
            tenant_id,
            exc,
        )


async def _deliver_one(
    session, row: OutboxRow, key, settings: EngineSettings, now: datetime
) -> None:
    try:
        signed = sign_policy_record(row.policy_payload, key)
    except Exception as exc:  # a payload that cannot be signed is permanently bad
        await mark_failed(session, outbox_id=row.outbox_id, error=f"sign failed: {exc!r}")
        logger.error(
            "delta.budget sign FAILED (dead-lettered, decision retained) policy_id=%s err=%r",
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
                "delta.budget publish DEAD-LETTERED (retries exhausted; decision retained, "
                "NOT lost) policy_id=%s version=%d err=%r",
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
                "delta.budget publish transient (retry %d/%d) policy_id=%s err=%r",
                attempts,
                settings.max_publish_attempts,
                row.policy_id,
                exc,
            )
        return
    except PermanentPublishError as exc:
        await mark_failed(session, outbox_id=row.outbox_id, error=str(exc))
        logger.error(
            "delta.budget publish REJECTED (dead-lettered, decision retained) policy_id=%s "
            "err=%r",
            row.policy_id,
            exc,
        )
        return

    await mark_distributed(
        session, outbox_id=row.outbox_id, distribution_id=result.distribution_id, now=now
    )
    logger.info(
        "delta.budget DISTRIBUTED policy_id=%s version=%d transition=%s distribution_id=%s",
        row.policy_id,
        row.policy_version,
        row.transition,
        result.distribution_id,
    )
