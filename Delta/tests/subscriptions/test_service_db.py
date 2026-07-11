"""D-022 service-layer DB tests: exception mapping, forward-only cancel lifecycle,
the D-009 audit-chain wiring, and the anomaly report's use of real recorded charges
(never hand-computed).

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as ``tests/erp/test_service_db.py``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from delta.erp.schemas import VendorCreateRequest
from delta.erp.service import create_vendor
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_tenant_session
from delta.subscriptions.schemas import (
    ChargeRecordRequest,
    SubscriptionAnomalyQuery,
    SubscriptionCancelRequest,
    SubscriptionCreateRequest,
)
from delta.subscriptions.service import (
    SubscriptionAlreadyCancelledError,
    SubscriptionNotFoundError,
    VendorNotFoundError,
    cancel_subscription,
    create_subscription,
    get_anomaly_report,
    record_charge,
)

from .conftest import db_required


def _charged_at(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


@db_required
async def test_create_subscription_missing_vendor_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(VendorNotFoundError):
            await create_subscription(
                session,
                SubscriptionCreateRequest(
                    tenant_id=tenant_id,
                    vendor_id="99999999-9999-4999-8999-999999999999",
                    name="Ghost subscription",
                    cadence="monthly",
                    created_by="Jane",
                ),
            )


@db_required
async def test_create_subscription_currency_defaults_when_amount_given(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id,
                name="Notion",
                expected_amount_minor_units=999,
                currency=None,
                cadence="monthly",
                created_by="Jane",
            ),
        )
    assert sub.expected_amount_minor_units == 999
    assert sub.currency == "USD"
    assert sub.status == "active"


@db_required
async def test_create_subscription_links_real_vendor(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor = await create_vendor(session, VendorCreateRequest(tenant_id=tenant_id, name="Acme"))

    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id,
                vendor_id=vendor.vendor_id,
                name="Acme Cloud",
                cadence="monthly",
                created_by="Jane",
            ),
        )
    assert sub.vendor_id == vendor.vendor_id


@db_required
async def test_cancel_already_cancelled_subscription_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Notion", cadence="monthly", created_by="Jane"
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        await cancel_subscription(
            session,
            subscription_id=sub.subscription_id,
            req=SubscriptionCancelRequest(tenant_id=tenant_id, actor="Bob"),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SubscriptionAlreadyCancelledError):
            await cancel_subscription(
                session,
                subscription_id=sub.subscription_id,
                req=SubscriptionCancelRequest(tenant_id=tenant_id, actor="Bob"),
            )


@db_required
async def test_cancel_missing_subscription_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SubscriptionNotFoundError):
            await cancel_subscription(
                session,
                subscription_id="99999999-9999-4999-8999-999999999999",
                req=SubscriptionCancelRequest(tenant_id=tenant_id, actor="Bob"),
            )


@db_required
async def test_record_charge_against_missing_subscription_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SubscriptionNotFoundError):
            await record_charge(
                session,
                subscription_id="99999999-9999-4999-8999-999999999999",
                req=ChargeRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=1000,
                    charged_at=datetime.now(timezone.utc),
                    recorded_by="Jane",
                ),
            )


@db_required
async def test_record_charge_against_cancelled_subscription_still_succeeds(tenant_id) -> None:
    # ADR-0022 Fork 4: a charge landing after cancellation is still a real, honest
    # financial fact and must be recordable.
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Notion", cadence="monthly", created_by="Jane"
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        await cancel_subscription(
            session,
            subscription_id=sub.subscription_id,
            req=SubscriptionCancelRequest(tenant_id=tenant_id, actor="Bob"),
        )
    async with get_tenant_session(tenant_id) as session:
        charge = await record_charge(
            session,
            subscription_id=sub.subscription_id,
            req=ChargeRecordRequest(
                tenant_id=tenant_id,
                amount_minor_units=999,
                charged_at=datetime.now(timezone.utc),
                recorded_by="Jane",
            ),
        )
    assert charge.amount_minor_units == 999


@db_required
async def test_subscription_lifecycle_lands_in_d009_audit_chain(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Notion", cadence="monthly", created_by="Jane"
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        charge = await record_charge(
            session,
            subscription_id=sub.subscription_id,
            req=ChargeRecordRequest(
                tenant_id=tenant_id,
                amount_minor_units=999,
                charged_at=datetime.now(timezone.utc),
                recorded_by="Jane",
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        await cancel_subscription(
            session,
            subscription_id=sub.subscription_id,
            req=SubscriptionCancelRequest(tenant_id=tenant_id, actor="Bob"),
        )

    async with get_tenant_session(tenant_id) as session:
        sub_rows = await list_history(
            session, entity_type="subscription", entity_id=sub.subscription_id
        )
        charge_rows = await list_history(
            session, entity_type="subscription_charge", entity_id=charge.charge_id
        )

    assert {r.action for r in sub_rows} == {"created", "cancelled"}
    assert {r.action for r in charge_rows} == {"recorded"}


@db_required
async def test_anomaly_report_detects_spend_spike_from_real_charges(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Cloud Hosting", cadence="monthly", created_by="Jane"
            ),
        )

    # 6 baseline charges @ $10, then one spike charge @ $80 (8x the baseline avg).
    for i, days_ago in enumerate([200, 170, 140, 110, 80, 50]):
        async with get_tenant_session(tenant_id) as session:
            await record_charge(
                session,
                subscription_id=sub.subscription_id,
                req=ChargeRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=1000,
                    charged_at=_charged_at(days_ago),
                    recorded_by="Jane",
                    note=f"baseline-{i}",
                ),
            )
    async with get_tenant_session(tenant_id) as session:
        await record_charge(
            session,
            subscription_id=sub.subscription_id,
            req=ChargeRecordRequest(
                tenant_id=tenant_id,
                amount_minor_units=8000,
                charged_at=_charged_at(1),
                recorded_by="Jane",
                note="spike",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        report = await get_anomaly_report(
            session, SubscriptionAnomalyQuery(tenant_id=tenant_id, baseline_window=6)
        )

    assert report.method == "trailing_average_ratio_v1"
    rows = {r.subscription_id: r for r in report.anomalies}
    assert sub.subscription_id in rows
    row = rows[sub.subscription_id]
    assert row.code == "SPEND_SPIKE"
    assert row.severity == "warning"
    assert row.current_charge_cents == 8000
    assert row.baseline_avg_cents == pytest.approx(1000.0)
    assert row.ratio == pytest.approx(8.0)


@db_required
async def test_anomaly_report_flat_charges_not_flagged(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Steady SaaS", cadence="monthly", created_by="Jane"
            ),
        )
    for days_ago in [180, 150, 120, 90, 60, 30, 1]:
        async with get_tenant_session(tenant_id) as session:
            await record_charge(
                session,
                subscription_id=sub.subscription_id,
                req=ChargeRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=1500,
                    charged_at=_charged_at(days_ago),
                    recorded_by="Jane",
                ),
            )

    async with get_tenant_session(tenant_id) as session:
        report = await get_anomaly_report(
            session, SubscriptionAnomalyQuery(tenant_id=tenant_id, baseline_window=6)
        )

    assert sub.subscription_id not in {r.subscription_id for r in report.anomalies}


@db_required
async def test_anomaly_report_first_charge_is_new_spender(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sub = await create_subscription(
            session,
            SubscriptionCreateRequest(
                tenant_id=tenant_id, name="Brand New Tool", cadence="monthly", created_by="Jane"
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        await record_charge(
            session,
            subscription_id=sub.subscription_id,
            req=ChargeRecordRequest(
                tenant_id=tenant_id,
                amount_minor_units=2000,
                charged_at=_charged_at(1),
                recorded_by="Jane",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        report = await get_anomaly_report(
            session, SubscriptionAnomalyQuery(tenant_id=tenant_id, baseline_window=6)
        )

    rows = {r.subscription_id: r for r in report.anomalies}
    assert rows[sub.subscription_id].code == "NEW_SPENDER"
    assert rows[sub.subscription_id].severity == "info"
