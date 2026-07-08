"""Chargeback/showback + anomaly-detection orchestration (D-012).

Both operations reuse D-008's ``dashboards.store.top_spenders`` unchanged — no new
aggregate query is written. A chargeback report is one call (current window, ranked +
percentage-of-total); anomaly detection is exactly two calls (current window + baseline
window), never one call per group — the same "small, fixed number of queries regardless
of how many groups exist" shape D-011's service layer uses.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ..dashboards import store as dashboards_store
from .anomaly import detect_anomalies
from .schemas import (
    AnomalyQuery,
    AnomalyReportView,
    AnomalyRow,
    ChargebackQuery,
    ChargebackReportView,
    ChargebackRow,
)

# Generous enough to capture every distinct group in practice (mirrors D-008's own
# top_spenders cap of 100) — a chargeback/showback report wants every department, not
# just a top-N ranking, but still bounded against a pathological number of distinct
# group values.
_MAX_GROUPS = 100


def _scope_of(query) -> dashboards_store.ScopeFilter:
    return dashboards_store.ScopeFilter(
        team_id=query.team_id, project_id=query.project_id, agent_id=query.agent_id
    )


async def get_chargeback_report(
    session: AsyncSession, query: ChargebackQuery
) -> ChargebackReportView:
    rows = await dashboards_store.top_spenders(
        session,
        start=query.start,
        end=query.end,
        group_by=query.group_by,
        scope=_scope_of(query),
        limit=_MAX_GROUPS,
    )
    total_cost_cents = sum(r.cost_cents for r in rows)
    return ChargebackReportView(
        total_cost_cents=total_cost_cents,
        rows=[
            ChargebackRow(
                group_key=r.group_key,
                cost_cents=r.cost_cents,
                request_count=r.request_count,
                share_pct=(r.cost_cents * 100 / total_cost_cents) if total_cost_cents > 0 else 0.0,
            )
            for r in rows
        ],
    )


async def get_anomaly_report(session: AsyncSession, query: AnomalyQuery) -> AnomalyReportView:
    baseline_start, baseline_end = query.baseline_window()
    scope = _scope_of(query)

    current_rows = await dashboards_store.top_spenders(
        session,
        start=query.start,
        end=query.end,
        group_by=query.group_by,
        scope=scope,
        limit=_MAX_GROUPS,
    )
    baseline_rows = await dashboards_store.top_spenders(
        session,
        start=baseline_start,
        end=baseline_end,
        group_by=query.group_by,
        scope=scope,
        limit=_MAX_GROUPS,
    )

    current_by_group = {r.group_key: r.cost_cents for r in current_rows}
    baseline_total_by_group = {r.group_key: r.cost_cents for r in baseline_rows}

    results = detect_anomalies(
        current_by_group=current_by_group,
        baseline_total_by_group=baseline_total_by_group,
        baseline_periods=query.baseline_periods,
    )

    return AnomalyReportView(
        baseline_periods=query.baseline_periods,
        baseline_start=baseline_start,
        baseline_end=baseline_end,
        anomalies=[
            AnomalyRow(
                group_key=r.group_key,
                current_spend_cents=r.current_spend_cents,
                baseline_avg_cents=r.baseline_avg_cents,
                ratio=r.ratio,
                code=r.code,
                severity=r.severity,
            )
            for r in results
        ],
    )
