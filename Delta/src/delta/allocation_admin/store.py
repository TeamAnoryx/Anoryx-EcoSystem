"""Allocation-admin persistence (D-007, ADR-0007 §5).

Tenant-scoped reads/writes against the ``allocations`` / ``allocation_targets`` tables
(migration 0005). Every function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
owns the transaction, exactly like ``budget_engine.definitions`` and
``kill_switch.state``.

The change-history log itself (``append_history``/``list_history``/``HistoryRecord``)
moved to ``delta.persistence.audit_log`` in D-009, which hash-chains it — a persistence-
layer concern shared by every automated financial workflow (allocations, budget-engine
and kill-switch enforcement), not something specific to allocation-admin.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..budget import BudgetPeriod, BudgetScope
from ..persistence.models import allocation_targets, allocations

# List-response bounds (finding #1, docs/audit/d-007-security-audit.md): an
# unbounded SELECT over a long-lived, append-only tenant grows without limit.
DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class AllocationTargetRecord:
    target_id: str
    allocation_id: str
    tenant_id: str
    scope: BudgetScope
    team_id: str
    project_id: str
    agent_id: str
    amount_minor_units: int
    budget_id: str | None


@dataclass(frozen=True)
class AllocationRecord:
    allocation_id: str
    tenant_id: str
    total_minor_units: int
    currency: str
    period: BudgetPeriod
    status: str
    requested_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    targets: tuple[AllocationTargetRecord, ...]


def _target_from_row(row) -> AllocationTargetRecord:
    return AllocationTargetRecord(
        target_id=row.target_id,
        allocation_id=row.allocation_id,
        tenant_id=row.tenant_id,
        scope=BudgetScope(row.scope),
        team_id=row.team_id,
        project_id=row.project_id,
        agent_id=row.agent_id,
        amount_minor_units=row.amount_minor_units,
        budget_id=row.budget_id,
    )


async def create_allocation(
    session: AsyncSession,
    *,
    tenant_id: str,
    total_minor_units: int,
    currency: str,
    period: BudgetPeriod,
    targets: list[dict],
    requested_by: str,
    now: datetime,
    allocation_id: str | None = None,
) -> AllocationRecord:
    """Persist a new allocation + its targets, status='requested'. Does NOT commit.

    ``targets`` items are dicts with keys ``scope, team_id, project_id, agent_id,
    amount_minor_units`` — the caller (``service.create_allocation_request``) has
    already validated the reconciliation invariant via ``delta.allocation.Allocation``
    before calling this.
    """
    aid = allocation_id or str(uuid.uuid4())
    await session.execute(
        insert(allocations).values(
            allocation_id=aid,
            tenant_id=tenant_id,
            total_minor_units=total_minor_units,
            currency=currency,
            period=period.value,
            status="requested",
            requested_by=requested_by,
            requested_at=now,
            decided_by=None,
            decided_at=None,
        )
    )
    target_records: list[AllocationTargetRecord] = []
    for t in targets:
        tid = str(uuid.uuid4())
        await session.execute(
            insert(allocation_targets).values(
                target_id=tid,
                allocation_id=aid,
                tenant_id=tenant_id,
                scope=t["scope"].value,
                team_id=t["team_id"],
                project_id=t["project_id"],
                agent_id=t["agent_id"],
                amount_minor_units=t["amount_minor_units"],
                budget_id=None,
            )
        )
        target_records.append(
            AllocationTargetRecord(
                target_id=tid,
                allocation_id=aid,
                tenant_id=tenant_id,
                scope=t["scope"],
                team_id=t["team_id"],
                project_id=t["project_id"],
                agent_id=t["agent_id"],
                amount_minor_units=t["amount_minor_units"],
                budget_id=None,
            )
        )
    return AllocationRecord(
        allocation_id=aid,
        tenant_id=tenant_id,
        total_minor_units=total_minor_units,
        currency=currency,
        period=period,
        status="requested",
        requested_by=requested_by,
        requested_at=now,
        decided_by=None,
        decided_at=None,
        targets=tuple(target_records),
    )


async def get_allocation(session: AsyncSession, *, allocation_id: str) -> AllocationRecord | None:
    """Fetch one allocation with its targets (RLS confines to the caller's tenant)."""
    row = (
        await session.execute(
            select(allocations).where(allocations.c.allocation_id == allocation_id)
        )
    ).first()
    if row is None:
        return None
    target_rows = (
        await session.execute(
            select(allocation_targets).where(allocation_targets.c.allocation_id == allocation_id)
        )
    ).all()
    return AllocationRecord(
        allocation_id=row.allocation_id,
        tenant_id=row.tenant_id,
        total_minor_units=row.total_minor_units,
        currency=row.currency,
        period=BudgetPeriod(row.period),
        status=row.status,
        requested_by=row.requested_by,
        requested_at=row.requested_at,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
        targets=tuple(_target_from_row(r) for r in target_rows),
    )


async def list_allocations(
    session: AsyncSession, *, status: str | None = None, limit: int = DEFAULT_LIST_LIMIT
) -> list[AllocationRecord]:
    """List allocations for the caller's tenant (RLS-confined), optionally by status.

    ``limit`` is clamped to ``[1, MAX_LIST_LIMIT]`` — the caller (router) may expose
    it, but this function never returns an unbounded result set on its own.
    """
    stmt = select(allocations)
    if status is not None:
        stmt = stmt.where(allocations.c.status == status)
    stmt = stmt.order_by(allocations.c.requested_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    records: list[AllocationRecord] = []
    for row in rows:
        target_rows = (
            await session.execute(
                select(allocation_targets).where(
                    allocation_targets.c.allocation_id == row.allocation_id
                )
            )
        ).all()
        records.append(
            AllocationRecord(
                allocation_id=row.allocation_id,
                tenant_id=row.tenant_id,
                total_minor_units=row.total_minor_units,
                currency=row.currency,
                period=BudgetPeriod(row.period),
                status=row.status,
                requested_by=row.requested_by,
                requested_at=row.requested_at,
                decided_by=row.decided_by,
                decided_at=row.decided_at,
                targets=tuple(_target_from_row(r) for r in target_rows),
            )
        )
    return records


async def try_decide_allocation(
    session: AsyncSession,
    *,
    allocation_id: str,
    new_status: str,
    decided_by: str,
    now: datetime,
) -> bool:
    """Conditionally transition 'requested' -> ``new_status``. Does NOT commit.

    Guards concurrent double-decision (the same race class as D-005's conditional
    ``UPDATE ... WHERE state='under'``): the WHERE clause only matches a row still
    'requested', so a second concurrent decision affects zero rows. Returns True iff
    this call performed the transition.
    """
    result = await session.execute(
        update(allocations)
        .where(allocations.c.allocation_id == allocation_id)
        .where(allocations.c.status == "requested")
        .values(status=new_status, decided_by=decided_by, decided_at=now)
    )
    return result.rowcount == 1


async def set_target_budget_id(session: AsyncSession, *, target_id: str, budget_id: str) -> None:
    """Record the budget_definitions row a target was materialized into. Does NOT commit."""
    await session.execute(
        update(allocation_targets)
        .where(allocation_targets.c.target_id == target_id)
        .values(budget_id=budget_id)
    )
