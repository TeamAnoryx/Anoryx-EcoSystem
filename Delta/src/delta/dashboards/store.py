"""Dashboard aggregate queries (D-008) — reads only, over ``ledger_entries`` (D-003).

Every usage event posts exactly one balanced two-leg transaction (D-004
``posting.py``): a DEBIT to the tenant's expense account, a CREDIT to a contra
account, both legs carrying the same team/project/agent/timestamp/amount. Summing
BOTH legs nets to zero (that is the point of double-entry); these queries filter
``direction = 'debit'`` so each usage event contributes exactly once — the expense
leg is "spend," not the balancing contra leg. This assumes every debit-direction
ledger row today is a usage-driven expense entry (true as of D-004/D-005/D-006/D-007
— no other Delta feature posts a debit yet); a future feature that posts a
non-usage debit would need to be excluded here explicitly, not silently blended in.

All queries run on a caller-supplied tenant-scoped ``AsyncSession`` (RLS confines
every row to the caller's tenant), mirroring ``persistence/balances.py``'s read
primitives — this module adds grouping/bucketing on top, it does not reimplement
the balance/movement primitives themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import Column, and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import ledger_entries

GroupDimension = Literal["team_id", "project_id", "agent_id"]
BucketGranularity = Literal["hour", "day"]

_DEBIT = "debit"

# Row cap for spend_time_series (independent security review finding #1,
# docs/audit/d-008-security-audit.md): the 400-day window cap alone still
# permits ~9,600 rows at hour granularity. This LIMIT bounds every call
# regardless of the window/bucket combination, mirroring D-007's list-response
# cap (store.MAX_LIST_LIMIT in allocation_admin).
_MAX_TIMESERIES_POINTS = 2000


@dataclass(frozen=True)
class ScopeFilter:
    """Optional caller-supplied narrowing ("client/team-set parameters")."""

    team_id: str | None = None
    project_id: str | None = None
    agent_id: str | None = None


@dataclass(frozen=True)
class SpendSummaryRow:
    total_cost_cents: int
    request_count: int
    window_hours: float

    @property
    def cost_per_request_cents(self) -> float | None:
        return None if self.request_count == 0 else self.total_cost_cents / self.request_count

    @property
    def burn_rate_cents_per_hour(self) -> float:
        return 0.0 if self.window_hours == 0 else self.total_cost_cents / self.window_hours


@dataclass(frozen=True)
class TimeSeriesPointRow:
    bucket_start: datetime
    cost_cents: int
    request_count: int


@dataclass(frozen=True)
class GroupSpendRow:
    group_key: str
    cost_cents: int
    request_count: int


def _scope_clauses(scope: ScopeFilter) -> list:
    c = ledger_entries.c
    clauses = []
    if scope.team_id is not None:
        clauses.append(c.team_id == scope.team_id)
    if scope.project_id is not None:
        clauses.append(c.project_id == scope.project_id)
    if scope.agent_id is not None:
        clauses.append(c.agent_id == scope.agent_id)
    return clauses


def _window_clause(*, start: datetime, end: datetime):
    c = ledger_entries.c
    # Half-open [start, end) — matches delta.usage.TimeWindow / burn_rate semantics.
    return and_(c.direction == _DEBIT, c.timestamp >= start, c.timestamp < end)


async def spend_summary(
    session: AsyncSession, *, start: datetime, end: datetime, scope: ScopeFilter | None = None
) -> SpendSummaryRow:
    """Total spend + request count over ``[start, end)``, optionally scoped."""
    stmt = select(
        func.coalesce(func.sum(ledger_entries.c.amount_minor_units), 0),
        func.count(),
    ).where(_window_clause(start=start, end=end), *_scope_clauses(scope or ScopeFilter()))
    row = (await session.execute(stmt)).one()
    window_hours = (end - start).total_seconds() / 3600.0
    return SpendSummaryRow(
        total_cost_cents=int(row[0]), request_count=int(row[1]), window_hours=window_hours
    )


async def spend_time_series(
    session: AsyncSession,
    *,
    start: datetime,
    end: datetime,
    bucket: BucketGranularity,
    scope: ScopeFilter | None = None,
) -> list[TimeSeriesPointRow]:
    """Spend + request count per time bucket over ``[start, end)``, optionally scoped."""
    bucket_col: Column = func.date_trunc(bucket, ledger_entries.c.timestamp).label("bucket_start")
    stmt = (
        select(
            bucket_col,
            func.coalesce(func.sum(ledger_entries.c.amount_minor_units), 0),
            func.count(),
        )
        .where(_window_clause(start=start, end=end), *_scope_clauses(scope or ScopeFilter()))
        .group_by(bucket_col)
        .order_by(bucket_col)
        .limit(_MAX_TIMESERIES_POINTS)
    )
    rows = (await session.execute(stmt)).all()
    return [
        TimeSeriesPointRow(bucket_start=r[0], cost_cents=int(r[1]), request_count=int(r[2]))
        for r in rows
    ]


async def top_spenders(
    session: AsyncSession,
    *,
    start: datetime,
    end: datetime,
    group_by: GroupDimension,
    scope: ScopeFilter | None = None,
    limit: int = 10,
) -> list[GroupSpendRow]:
    """Top ``limit`` spenders by ``group_by`` dimension over ``[start, end)``.

    ``scope`` narrows the population BEFORE grouping/ranking (e.g. rank agents
    within one project) — it is never the same field as ``group_by`` (the router
    rejects that combination as a no-op request).
    """
    group_col = getattr(ledger_entries.c, group_by)
    stmt = (
        select(
            group_col,
            func.coalesce(func.sum(ledger_entries.c.amount_minor_units), 0),
            func.count(),
        )
        .where(_window_clause(start=start, end=end), *_scope_clauses(scope or ScopeFilter()))
        .group_by(group_col)
        .order_by(func.sum(ledger_entries.c.amount_minor_units).desc())
        .limit(max(1, min(limit, 100)))
    )
    rows = (await session.execute(stmt)).all()
    return [
        GroupSpendRow(group_key=r[0], cost_cents=int(r[1]), request_count=int(r[2])) for r in rows
    ]


async def spend_for_groups(
    session: AsyncSession,
    *,
    start: datetime,
    end: datetime,
    group_by: GroupDimension,
    group_keys: list[str],
    scope: ScopeFilter | None = None,
) -> list[GroupSpendRow]:
    """Spend + request count for a SPECIFIC, caller-supplied set of ``group_by`` values
    over ``[start, end)`` — unlike ``top_spenders``, this does not rank or apply its own
    limit; the caller already knows exactly which groups it needs (e.g. D-012's anomaly
    baseline lookup, which must match the group_keys ``top_spenders`` returned for the
    CURRENT window, not whichever groups separately happen to rank in the top-N of a
    different window — a group could be a top-N spender now but rank outside a blind
    top-N baseline query, silently reading as "no prior spend"). ``group_keys`` is
    expected to already be bounded by the caller (mirrors ``top_spenders``'s own
    100-row cap); this returns no rows for an empty list without issuing a query.
    """
    if not group_keys:
        return []
    group_col = getattr(ledger_entries.c, group_by)
    stmt = (
        select(
            group_col,
            func.coalesce(func.sum(ledger_entries.c.amount_minor_units), 0),
            func.count(),
        )
        .where(
            _window_clause(start=start, end=end),
            group_col.in_(group_keys[:100]),
            *_scope_clauses(scope or ScopeFilter()),
        )
        .group_by(group_col)
    )
    rows = (await session.execute(stmt)).all()
    return [
        GroupSpendRow(group_key=r[0], cost_cents=int(r[1]), request_count=int(r[2])) for r in rows
    ]
