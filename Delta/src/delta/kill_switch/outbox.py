"""Kill-switch publish outbox — the durable kill/clear decision + delivery state
(ADR-0006 §3.4, mirrors ``budget_engine.outbox`` exactly).

The decision is committed here in the SAME transaction as the state-flip in
``state.py``, BEFORE any network call, so a decision is never lost if O-004 is down or
the process dies. The drainer signs the payload fresh and POSTs it; delivery outcomes
update this row. The ``failed`` state is the dead-letter. The UNIQUE
``(tenant, policy_id, policy_version)`` makes a re-evaluated offense a no-op insert —
defence-in-depth on top of the conditional state transition.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import kill_switch_outbox as _kso


@dataclass(frozen=True)
class KillOutboxRow:
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
    kill_id: str,
    policy_id: str,
    policy_version: int,
    transition: str,
    policy_payload: dict[str, Any],
    now: datetime,
) -> None:
    """Persist the kill/clear decision (no-op if this (policy, version) is already queued)."""
    await session.execute(
        pg_insert(_kso)
        .values(
            outbox_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            kill_id=kill_id,
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
    """Read-only snapshot of pending outbox ids due for (re)delivery (no lock)."""
    stmt = (
        select(_kso.c.outbox_id)
        .where(and_(_kso.c.state == "pending", _kso.c.next_attempt_at <= now))
        .order_by(_kso.c.created_at)
        .limit(limit)
    )
    return [r[0] for r in (await session.execute(stmt)).all()]


async def claim_one(
    session: AsyncSession, *, outbox_id: str, now: datetime
) -> KillOutboxRow | None:
    """Lock one still-pending, still-due row by id (FOR UPDATE SKIP LOCKED) or return None."""
    stmt = (
        select(_kso)
        .where(
            and_(
                _kso.c.outbox_id == outbox_id,
                _kso.c.state == "pending",
                _kso.c.next_attempt_at <= now,
            )
        )
        .with_for_update(skip_locked=True)
    )
    r = (await session.execute(stmt)).first()
    if r is None:
        return None
    return KillOutboxRow(
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
        update(_kso)
        .where(_kso.c.outbox_id == outbox_id)
        .values(
            state="distributed",
            distribution_id=distribution_id,
            attempts=_kso.c.attempts + 1,
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
    await session.execute(
        update(_kso)
        .where(_kso.c.outbox_id == outbox_id)
        .values(
            attempts=_kso.c.attempts + 1,
            next_attempt_at=next_attempt_at,
            last_error=error[:512],
        )
    )


async def mark_failed(session: AsyncSession, *, outbox_id: str, error: str) -> None:
    await session.execute(
        update(_kso)
        .where(_kso.c.outbox_id == outbox_id)
        .values(state="failed", attempts=_kso.c.attempts + 1, last_error=error[:512])
    )
