"""Enforcement-state store — edge detection + idempotent publish (ADR-0005 §3.3).

A per-(tenant, budget, period-window) row tracks ``under``/``enforced``. The publish
decision is gated by a CONDITIONAL transition: ``UPDATE ... WHERE state='under'`` (or
``='enforced'`` for un-enforce). Postgres evaluates the row-count, so under concurrent
appends both crossing the cap exactly one transaction flips the state and publishes —
the loser's UPDATE matches zero rows and does not publish (vector 5). The version is
bumped IN the same UPDATE (``last_published_version + 1``, RHS uses the pre-image) and
returned via ``RETURNING`` (the post-image), so it is monotonic and race-free; Sentinel
rejects replay (``version <= current_max``), so every publish must use a fresh version.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import and_, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import budget_enforcement_state as _bes


@dataclass(frozen=True)
class EnforcementState:
    state_id: str
    tenant_id: str
    budget_id: str
    period_bucket: str
    state: str
    enforced_policy_version: int | None
    last_published_version: int
    last_warned_pct: int | None


def _row_to_state(row) -> EnforcementState:
    return EnforcementState(
        state_id=row.state_id,
        tenant_id=row.tenant_id,
        budget_id=row.budget_id,
        period_bucket=row.period_bucket,
        state=row.state,
        enforced_policy_version=row.enforced_policy_version,
        last_published_version=row.last_published_version,
        last_warned_pct=row.last_warned_pct,
    )


async def get_or_create_state(
    session: AsyncSession,
    *,
    tenant_id: str,
    budget_id: str,
    period_bucket: str,
    now: datetime,
) -> EnforcementState:
    """Return the state row for (tenant, budget, window), creating it ``under`` if new.

    A new period's row seeds ``last_published_version`` from the GLOBAL max across all prior
    periods of this (tenant, budget), NOT 0 — because ``policy_version`` is monotonic per
    ``policy_id`` globally (the outbox UNIQUE(tenant, policy_id, version) and Sentinel's
    replay protection are both per-policy_id, not per-period). Resetting to 0 each period
    would recompute an already-used version, whose outbox INSERT would silently no-op
    (on-conflict) — a missed enforcement that logs/state would falsely report as enforced.
    """
    seed_version = (
        select(func.coalesce(func.max(_bes.c.last_published_version), 0))
        .where(and_(_bes.c.tenant_id == tenant_id, _bes.c.budget_id == budget_id))
        .scalar_subquery()
    )
    await session.execute(
        pg_insert(_bes)
        .values(
            state_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            budget_id=budget_id,
            period_bucket=period_bucket,
            state="under",
            enforced_policy_version=None,
            last_published_version=seed_version,
            last_warned_pct=None,
            updated_at=now,
        )
        .on_conflict_do_nothing(
            index_elements=["tenant_id", "budget_id", "period_bucket"],
        )
    )
    row = (
        await session.execute(
            select(_bes).where(
                and_(
                    _bes.c.tenant_id == tenant_id,
                    _bes.c.budget_id == budget_id,
                    _bes.c.period_bucket == period_bucket,
                )
            )
        )
    ).one()
    return _row_to_state(row)


async def _conditional_transition(
    session: AsyncSession,
    *,
    tenant_id: str,
    budget_id: str,
    period_bucket: str,
    from_state: str,
    to_state: str,
    set_enforced_version: bool,
    now: datetime,
) -> int | None:
    """Flip from_state->to_state iff currently from_state; return the new version or None.

    The new ``last_published_version`` is the pre-image + 1 (computed in-SQL) and returned
    via RETURNING (the post-image), so concurrent callers cannot collide on a version.
    """
    new_version = _bes.c.last_published_version + 1
    values = {
        "state": to_state,
        "last_published_version": new_version,
        "updated_at": now,
        "enforced_policy_version": new_version if set_enforced_version else None,
    }
    stmt = (
        update(_bes)
        .where(
            and_(
                _bes.c.tenant_id == tenant_id,
                _bes.c.budget_id == budget_id,
                _bes.c.period_bucket == period_bucket,
                _bes.c.state == from_state,
            )
        )
        .values(**values)
        .returning(_bes.c.last_published_version)
    )
    row = (await session.execute(stmt)).first()
    return int(row[0]) if row is not None else None


async def try_transition_to_enforced(
    session: AsyncSession, *, tenant_id: str, budget_id: str, period_bucket: str, now: datetime
) -> int | None:
    """under -> enforced. Returns the new policy version to publish, or None if it lost."""
    return await _conditional_transition(
        session,
        tenant_id=tenant_id,
        budget_id=budget_id,
        period_bucket=period_bucket,
        from_state="under",
        to_state="enforced",
        set_enforced_version=True,
        now=now,
    )


async def try_transition_to_under(
    session: AsyncSession, *, tenant_id: str, budget_id: str, period_bucket: str, now: datetime
) -> int | None:
    """enforced -> under (budget raised / un-enforce). Returns the new refresh version."""
    return await _conditional_transition(
        session,
        tenant_id=tenant_id,
        budget_id=budget_id,
        period_bucket=period_bucket,
        from_state="enforced",
        to_state="under",
        set_enforced_version=False,
        now=now,
    )


async def try_bump_warned_pct(
    session: AsyncSession,
    *,
    tenant_id: str,
    budget_id: str,
    period_bucket: str,
    pct: int,
    now: datetime,
) -> bool:
    """Record a newly-crossed soft-warning band (advisory only). True iff this is new.

    Edge-dedup: only succeeds when ``pct`` is higher than any band already warned this
    window, so a warning fires once per band per period — never on every append.
    """
    stmt = (
        update(_bes)
        .where(
            and_(
                _bes.c.tenant_id == tenant_id,
                _bes.c.budget_id == budget_id,
                _bes.c.period_bucket == period_bucket,
                (_bes.c.last_warned_pct.is_(None)) | (_bes.c.last_warned_pct < pct),
            )
        )
        .values(last_warned_pct=pct, updated_at=now)
        .returning(_bes.c.last_warned_pct)
    )
    row = (await session.execute(stmt)).first()
    return row is not None
