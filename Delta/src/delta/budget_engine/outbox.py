"""Publish outbox — the durable enforcement decision + delivery state (ADR-0005 §3.4).

The decision (the policy payload to publish) is committed here in the SAME transaction as
the enforcement-state flip, BEFORE any network call, so a decision is never lost if O-004
is down or the process dies (vector 11). A drainer signs the payload fresh and POSTs it;
delivery outcomes update the row. The ``failed`` state is the dead-letter (the outbox
doubles as the DLQ). The UNIQUE (tenant, policy_id, policy_version) makes a re-evaluated
crossing a no-op insert — defence-in-depth on the conditional transition (vector 5).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import budget_publish_outbox as _bpo


@dataclass(frozen=True)
class OutboxRow:
    outbox_id: str
    tenant_id: str
    policy_id: str
    policy_version: int
    transition: str
    policy_payload: dict[str, Any]
    attempts: int


async def enqueue_decision(
    session: AsyncSession,
    *,
    tenant_id: str,
    budget_id: str,
    policy_id: str,
    policy_version: int,
    transition: str,
    policy_payload: dict[str, Any],
    now: datetime,
) -> None:
    """Persist the enforcement decision (no-op if this (policy, version) is already queued)."""
    await session.execute(
        pg_insert(_bpo)
        .values(
            outbox_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            budget_id=budget_id,
            policy_id=policy_id,
            policy_version=policy_version,
            transition=transition,
            policy_payload=policy_payload,
            distribution_id=None,
            state="pending",
            attempts=0,
            next_attempt_at=now,
            last_error=None,
            created_at=now,
        )
        .on_conflict_do_nothing(
            index_elements=["tenant_id", "policy_id", "policy_version"],
        )
    )


async def due_outbox_ids(session: AsyncSession, *, now: datetime, limit: int = 64) -> list[str]:
    """Read-only snapshot of pending outbox ids due for (re)delivery (no lock).

    The drainer takes this snapshot then processes each id in its OWN transaction (via
    :func:`claim_one`), so a commit failure on one row never rolls back already-recorded
    deliveries of other rows (review MED). The snapshot is per drain call, so each row is
    attempted at most once per call.
    """
    stmt = (
        select(_bpo.c.outbox_id)
        .where(and_(_bpo.c.state == "pending", _bpo.c.next_attempt_at <= now))
        .order_by(_bpo.c.created_at)
        .limit(limit)
    )
    return [r[0] for r in (await session.execute(stmt)).all()]


async def claim_one(session: AsyncSession, *, outbox_id: str, now: datetime) -> OutboxRow | None:
    """Lock one still-pending, still-due row by id (FOR UPDATE SKIP LOCKED) or return None.

    Returns None when the row was already taken by a concurrent drainer, delivered, or is no
    longer due — the caller skips it. The lock is held for this row's own transaction only.
    """
    stmt = (
        select(_bpo)
        .where(
            and_(
                _bpo.c.outbox_id == outbox_id,
                _bpo.c.state == "pending",
                _bpo.c.next_attempt_at <= now,
            )
        )
        .with_for_update(skip_locked=True)
    )
    r = (await session.execute(stmt)).first()
    if r is None:
        return None
    return OutboxRow(
        outbox_id=r.outbox_id,
        tenant_id=r.tenant_id,
        policy_id=r.policy_id,
        policy_version=r.policy_version,
        transition=r.transition,
        policy_payload=r.policy_payload,
        attempts=r.attempts,
    )


async def mark_distributed(
    session: AsyncSession, *, outbox_id: str, distribution_id: str, now: datetime
) -> None:
    await session.execute(
        update(_bpo)
        .where(_bpo.c.outbox_id == outbox_id)
        .values(
            state="distributed",
            distribution_id=distribution_id,
            attempts=_bpo.c.attempts + 1,
            last_error=None,
        )
    )


async def mark_retry(
    session: AsyncSession,
    *,
    outbox_id: str,
    error: str,
    next_attempt_at: datetime,
) -> None:
    """Leave the row pending with a bumped attempt count + later next_attempt_at."""
    await session.execute(
        update(_bpo)
        .where(_bpo.c.outbox_id == outbox_id)
        .values(
            attempts=_bpo.c.attempts + 1,
            next_attempt_at=next_attempt_at,
            last_error=error[:512],
        )
    )


async def mark_failed(session: AsyncSession, *, outbox_id: str, error: str) -> None:
    """Move the row to the dead-letter state (retries exhausted / permanent rejection)."""
    await session.execute(
        update(_bpo)
        .where(_bpo.c.outbox_id == outbox_id)
        .values(state="failed", attempts=_bpo.c.attempts + 1, last_error=error[:512])
    )
