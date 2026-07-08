"""DB-backed chargeback/anomaly service tests (D-012): real ledger rows via the D-004
posting path, real RLS isolation. Every test uses explicit, caller-pinned windows (no
"now" dependency at all — unlike D-011's forecasting, chargeback/anomaly windows are
always caller-specified, never tied to a budget's implicit current period). Mirrors
``tests/dashboards/test_store_db.py``'s use of the production ``get_tenant_session``
directly (not a test-harness fixture).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from delta.chargeback.schemas import AnomalyQuery, ChargebackQuery
from delta.chargeback.service import get_anomaly_report, get_chargeback_report
from delta.persistence.database import get_tenant_session

from .conftest import db_required

pytestmark = db_required

_CURRENT_START = "2026-07-08T00:00:00Z"
_CURRENT_END = "2026-07-09T00:00:00Z"


def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


async def test_chargeback_report_computes_share_pct(tenant_id, seed_usage):
    team_a = str(uuid.uuid4())
    team_b = str(uuid.uuid4())
    await seed_usage(
        tenant_id=tenant_id, team_id=team_a, cost_cents=700_00, timestamp=_CURRENT_START
    )
    await seed_usage(
        tenant_id=tenant_id, team_id=team_b, cost_cents=300_00, timestamp=_CURRENT_START
    )

    query = ChargebackQuery(
        tenant_id=tenant_id, start=_dt(_CURRENT_START), end=_dt(_CURRENT_END), group_by="team_id"
    )
    async with get_tenant_session(tenant_id) as s:
        report = await get_chargeback_report(s, query)

    assert report.total_cost_cents == 1000_00
    by_key = {r.group_key: r for r in report.rows}
    assert by_key[team_a].cost_cents == 700_00
    assert by_key[team_a].share_pct == 70.0
    assert by_key[team_b].share_pct == 30.0


async def test_chargeback_report_empty_window_has_zero_total(tenant_id):
    query = ChargebackQuery(
        tenant_id=tenant_id, start=_dt(_CURRENT_START), end=_dt(_CURRENT_END), group_by="team_id"
    )
    async with get_tenant_session(tenant_id) as s:
        report = await get_chargeback_report(s, query)
    assert report.total_cost_cents == 0
    assert report.rows == []


async def test_chargeback_report_cross_tenant_isolation(tenant_id, other_tenant_id, seed_usage):
    await seed_usage(tenant_id=tenant_id, cost_cents=999_00, timestamp=_CURRENT_START)

    query = ChargebackQuery(
        tenant_id=other_tenant_id,
        start=_dt(_CURRENT_START),
        end=_dt(_CURRENT_END),
        group_by="team_id",
    )
    async with get_tenant_session(other_tenant_id) as s:
        report = await get_chargeback_report(s, query)
    assert report.total_cost_cents == 0


async def test_anomaly_report_detects_spend_spike(tenant_id, seed_usage):
    team = str(uuid.uuid4())
    # 7 baseline days at $10/day (avg $10/day), current day at $50 -> 5x, flagged.
    for day in range(1, 8):
        await seed_usage(
            tenant_id=tenant_id,
            team_id=team,
            cost_cents=10_00,
            timestamp=f"2026-07-{day:02d}T06:00:00Z",
        )
    await seed_usage(tenant_id=tenant_id, team_id=team, cost_cents=50_00, timestamp=_CURRENT_START)

    query = AnomalyQuery(
        tenant_id=tenant_id,
        start=_dt(_CURRENT_START),
        end=_dt(_CURRENT_END),
        group_by="team_id",
        baseline_periods=7,
    )
    async with get_tenant_session(tenant_id) as s:
        result = await get_anomaly_report(s, query)

    assert result.method == "trailing_average_ratio_v1"
    assert result.baseline_periods == 7
    assert len(result.anomalies) == 1
    row = result.anomalies[0]
    assert row.group_key == team
    assert row.code == "SPEND_SPIKE"
    assert row.current_spend_cents == 50_00
    assert row.baseline_avg_cents == 10_00
    assert row.ratio == 5.0


async def test_anomaly_report_detects_new_spender(tenant_id, seed_usage):
    team = str(uuid.uuid4())
    # No baseline-window usage at all for this team; only a current-window spend.
    await seed_usage(tenant_id=tenant_id, team_id=team, cost_cents=50_00, timestamp=_CURRENT_START)

    query = AnomalyQuery(
        tenant_id=tenant_id,
        start=_dt(_CURRENT_START),
        end=_dt(_CURRENT_END),
        group_by="team_id",
        baseline_periods=7,
    )
    async with get_tenant_session(tenant_id) as s:
        result = await get_anomaly_report(s, query)

    assert len(result.anomalies) == 1
    row = result.anomalies[0]
    assert row.code == "NEW_SPENDER"
    assert row.ratio is None
    assert row.baseline_avg_cents == 0.0


async def test_anomaly_report_flat_spend_produces_no_anomalies(tenant_id, seed_usage):
    team = str(uuid.uuid4())
    for day in range(1, 8):
        await seed_usage(
            tenant_id=tenant_id,
            team_id=team,
            cost_cents=20_00,
            timestamp=f"2026-07-{day:02d}T06:00:00Z",
        )
    await seed_usage(tenant_id=tenant_id, team_id=team, cost_cents=20_00, timestamp=_CURRENT_START)

    query = AnomalyQuery(
        tenant_id=tenant_id,
        start=_dt(_CURRENT_START),
        end=_dt(_CURRENT_END),
        group_by="team_id",
        baseline_periods=7,
    )
    async with get_tenant_session(tenant_id) as s:
        result = await get_anomaly_report(s, query)

    assert result.anomalies == []


async def test_anomaly_report_cross_tenant_isolation(tenant_id, other_tenant_id, seed_usage):
    await seed_usage(tenant_id=tenant_id, cost_cents=999_00, timestamp=_CURRENT_START)

    query = AnomalyQuery(
        tenant_id=other_tenant_id,
        start=_dt(_CURRENT_START),
        end=_dt(_CURRENT_END),
        group_by="team_id",
        baseline_periods=7,
    )
    async with get_tenant_session(other_tenant_id) as s:
        result = await get_anomaly_report(s, query)
    assert result.anomalies == []
