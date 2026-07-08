"""Chargeback/showback + anomaly-detection orchestration (D-012).

Both operations reuse D-008's ``dashboards.store`` aggregates — no new SQL beyond
``spend_for_groups`` (added alongside this task, same shape as ``top_spenders`` but
filtered to a caller-supplied group set instead of ranked+limited). A chargeback report
is two calls (an unbounded ``spend_summary`` for the true total, plus ``top_spenders`` for
the ranked group breakdown — the summary call keeps ``share_pct`` correct even when more
than ``_MAX_GROUPS`` distinct groups exist, since it isn't just the top-N rows summed).
Anomaly detection is exactly two calls (current window's ``top_spenders`` + baseline
window's ``spend_for_groups`` FOR THOSE SAME group keys, not a second, independent
top-N ranking of the baseline window — a group can rank in the current window's top-N
while its own baseline spend ranks outside a blind top-N baseline query, which would
otherwise silently misread a real prior spend as zero). Both operations stay a small,
fixed number of queries regardless of how many groups exist — the same shape D-011's
service layer uses.
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
    scope = _scope_of(query)
    summary = await dashboards_store.spend_summary(
        session, start=query.start, end=query.end, scope=scope
    )
    rows = await dashboards_store.top_spenders(
        session,
        start=query.start,
        end=query.end,
        group_by=query.group_by,
        scope=scope,
        limit=_MAX_GROUPS,
    )
    # The true total (unbounded by _MAX_GROUPS), not the sum of the ranked rows below —
    # keeps share_pct correct (and honestly < 100% in aggregate) when more than
    # _MAX_GROUPS distinct groups exist, instead of silently inflating each shown row's
    # share against a truncated denominator.
    total_cost_cents = summary.total_cost_cents
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
    current_by_group = {r.group_key: r.cost_cents for r in current_rows}

    # Fetch baseline totals for exactly the groups the CURRENT window returned — not a
    # second, independent top-N ranking of the baseline window, which could miss a group
    # whose baseline spend happens to rank outside the baseline window's own top-N even
    # though it's a top-N spender now (see docs/audit/d-012-security-audit.md finding #1).
    baseline_rows = await dashboards_store.spend_for_groups(
        session,
        start=baseline_start,
        end=baseline_end,
        group_by=query.group_by,
        group_keys=list(current_by_group.keys()),
        scope=scope,
    )
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
