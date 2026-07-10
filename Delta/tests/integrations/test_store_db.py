"""D-019 non-stubbed sync-connector persistence suite: real store writes -> real SQL
reads, real RLS. Mirrors ``tests/invoicing/test_store_db.py``'s shape."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.integrations import store
from delta.persistence.database import get_tenant_session

from .conftest import db_required, seed_approved_invoice, seed_approved_po

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


@db_required
async def test_create_and_get_external_system_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_external_system(
            session,
            tenant_id=tenant_id,
            name="Corp NetSuite",
            system_type="corporate_erp",
            vendor_label="NetSuite",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_external_system(session, system_id=created.system_id)

    assert fetched is not None
    assert fetched.status == "active"
    assert fetched.vendor_label == "NetSuite"


@db_required
async def test_list_external_systems_ordered_newest_first(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await store.create_external_system(
            session,
            tenant_id=tenant_id,
            name="First",
            system_type="corporate_erp",
            vendor_label="NetSuite",
            now=_NOW,
        )
        await store.create_external_system(
            session,
            tenant_id=tenant_id,
            name="Second",
            system_type="cloud_cost",
            vendor_label="AWS",
            now=_NOW + timedelta(minutes=1),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.list_external_systems(session)
    assert [r.name for r in rows] == ["Second", "First"]


@db_required
async def test_get_purchase_order_for_match_returns_target(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        _vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=50_000, currency="USD"
        )

    async with get_tenant_session(tenant_id) as session:
        target = await store.get_purchase_order_for_match(session, po_id=po_id)
    assert target is not None
    assert target.amount_minor_units == 50_000
    assert target.currency == "USD"


@db_required
async def test_get_purchase_order_for_match_returns_none_for_missing(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        target = await store.get_purchase_order_for_match(session, po_id="does-not-exist")
    assert target is None


@db_required
async def test_get_invoice_for_match_returns_target(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)
    invoice_id = await seed_approved_invoice(
        tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount_minor_units=25_000
    )

    async with get_tenant_session(tenant_id) as session:
        target = await store.get_invoice_for_match(session, invoice_id=invoice_id)
    assert target is not None
    assert target.amount_minor_units == 25_000


@db_required
async def test_create_sync_run_and_line_items_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        system = await store.create_external_system(
            session,
            tenant_id=tenant_id,
            name="AWS Cost Explorer",
            system_type="cloud_cost",
            vendor_label="AWS",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        run = await store.create_sync_run(
            session,
            tenant_id=tenant_id,
            system_id=system.system_id,
            triggered_by="ops@example.com",
            started_at=_NOW,
            completed_at=_NOW,
            records_matched=1,
            records_mismatched=0,
            records_not_found=0,
            records_unreconciled=2,
            note="monthly sync",
        )
        await store.create_sync_line_item(
            session,
            tenant_id=tenant_id,
            sync_run_id=run.sync_run_id,
            external_reference="EC2-INSTANCE-1",
            amount_minor_units=500,
            currency="USD",
            matched_status="unreconciled",
            matched_entity_type=None,
            matched_entity_id=None,
            now=_NOW,
        )
        await session.commit()

    assert run.records_ingested == 3

    async with get_tenant_session(tenant_id) as session:
        fetched_run = await store.get_sync_run(session, sync_run_id=run.sync_run_id)
        items = await store.list_sync_line_items(session, sync_run_id=run.sync_run_id)
    assert fetched_run is not None
    assert fetched_run.records_unreconciled == 2
    assert len(items) == 1
    assert items[0].matched_status == "unreconciled"


@db_required
async def test_compute_system_reconciliation_aggregates_across_runs(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        system = await store.create_external_system(
            session,
            tenant_id=tenant_id,
            name="Corp NetSuite",
            system_type="corporate_erp",
            vendor_label="NetSuite",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        run1 = await store.create_sync_run(
            session,
            tenant_id=tenant_id,
            system_id=system.system_id,
            triggered_by="ops@example.com",
            started_at=_NOW,
            completed_at=_NOW,
            records_matched=1,
            records_mismatched=1,
            records_not_found=0,
            records_unreconciled=0,
            note=None,
        )
        await store.create_sync_line_item(
            session,
            tenant_id=tenant_id,
            sync_run_id=run1.sync_run_id,
            external_reference="A",
            amount_minor_units=100,
            currency="USD",
            matched_status="matched",
            matched_entity_type="purchase_order",
            matched_entity_id="po-1",
            now=_NOW,
        )
        await store.create_sync_line_item(
            session,
            tenant_id=tenant_id,
            sync_run_id=run1.sync_run_id,
            external_reference="B",
            amount_minor_units=200,
            currency="USD",
            matched_status="amount_mismatch",
            matched_entity_type="purchase_order",
            matched_entity_id="po-2",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        row = await store.compute_system_reconciliation(session, system_id=system.system_id)
    assert row.total_runs == 1
    assert row.matched_count == 1
    assert row.mismatched_count == 1
    assert row.mismatched_amount_minor_units == 200


@db_required
async def test_cross_tenant_external_system_is_invisible(tenant_id, other_tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        system = await store.create_external_system(
            session,
            tenant_id=tenant_id,
            name="Corp NetSuite",
            system_type="corporate_erp",
            vendor_label="NetSuite",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_external_system(session, system_id=system.system_id)
    assert fetched is None
