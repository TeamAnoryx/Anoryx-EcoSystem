"""Dashboard orchestration (D-008): query validation -> store aggregate -> view."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from . import store
from .schemas import (
    DashboardQuery,
    GroupSpendView,
    SpendSummaryView,
    TimeSeriesPointView,
    TimeSeriesQuery,
    TopSpendersQuery,
)


def _scope_of(query: DashboardQuery) -> store.ScopeFilter:
    return store.ScopeFilter(
        team_id=query.team_id, project_id=query.project_id, agent_id=query.agent_id
    )


async def get_summary(session: AsyncSession, query: DashboardQuery) -> SpendSummaryView:
    row = await store.spend_summary(
        session, start=query.start, end=query.end, scope=_scope_of(query)
    )
    return SpendSummaryView(
        total_cost_cents=row.total_cost_cents,
        request_count=row.request_count,
        cost_per_request_cents=row.cost_per_request_cents,
        burn_rate_cents_per_hour=row.burn_rate_cents_per_hour,
    )


async def get_time_series(
    session: AsyncSession, query: TimeSeriesQuery
) -> list[TimeSeriesPointView]:
    rows = await store.spend_time_series(
        session,
        start=query.start,
        end=query.end,
        bucket=query.bucket,
        scope=_scope_of(query),
    )
    return [
        TimeSeriesPointView(
            bucket_start=r.bucket_start, cost_cents=r.cost_cents, request_count=r.request_count
        )
        for r in rows
    ]


async def get_top_spenders(session: AsyncSession, query: TopSpendersQuery) -> list[GroupSpendView]:
    rows = await store.top_spenders(
        session,
        start=query.start,
        end=query.end,
        group_by=query.group_by,
        scope=_scope_of(query),
        limit=query.limit,
    )
    return [
        GroupSpendView(
            group_key=r.group_key, cost_cents=r.cost_cents, request_count=r.request_count
        )
        for r in rows
    ]
