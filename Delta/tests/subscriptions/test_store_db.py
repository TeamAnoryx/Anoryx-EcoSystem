"""D-022 store-layer DB tests: the windowed recent-charges query (ADR-0021 Fork 3) and
the append-only grant on ``subscription_charges`` (ADR-0021 Fork 5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from delta.persistence.database import get_privileged_session, get_tenant_session
from delta.subscriptions.schemas import SubscriptionCreateRequest
from delta.subscriptions.service import create_subscription
from delta.subscriptions.store import list_recent_charges_by_subscription

from .conftest import db_required


def _charged_at(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


@db_required
async def test_list_recent_charges_returns_only_the_windowed_tail_per_subscription(
    tenant_id,
) -> None:
    from delta.subscriptions.schemas import ChargeRecordRequest
    from delta.subscriptions.service import record_charge

    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Notion", cadence="monthly", created_by="Jane"
            ),
        )

    # 10 charges recorded; window_size=3 should return only the 4 most recent
    # (window_size + 1: the current one plus 3 baseline priors), newest first.
    for days_ago in range(10, 0, -1):
        async with get_tenant_session(tenant_id) as session:
            await record_charge(
                session,
                subscription_id=sub.subscription_id,
                req=ChargeRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=1000 + days_ago,
                    charged_at=_charged_at(days_ago),
                    recorded_by="Jane",
                ),
            )

    async with get_tenant_session(tenant_id) as session:
        by_sub = await list_recent_charges_by_subscription(
            session, subscription_ids=[sub.subscription_id], window_size=3
        )

    charges = by_sub[sub.subscription_id]
    assert len(charges) == 4
    # amount_minor_units = 1000 + days_ago, so newest-first (ascending days_ago) is
    # ascending amount: the charge recorded 1 day ago (amount 1001) leads, then the
    # charges recorded 2/3/4 days ago.
    assert [c.amount_minor_units for c in charges] == [1001, 1002, 1003, 1004]


@db_required
async def test_list_recent_charges_empty_subscription_ids_short_circuits(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        by_sub = await list_recent_charges_by_subscription(
            session, subscription_ids=[], window_size=6
        )
    assert by_sub == {}


@db_required
async def test_subscription_charges_table_has_no_update_delete_grant() -> None:
    async with get_privileged_session() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'delta' AND table_name = 'subscription_charges' "
                    "AND grantee = 'delta_app'"
                )
            )
        ).all()
    privileges = {r[0] for r in rows}
    assert privileges == {"SELECT", "INSERT"}
