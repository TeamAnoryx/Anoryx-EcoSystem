"""D-014 non-stubbed ERP persistence suite: real store writes -> real SQL reads, real
RLS. Mirrors ``tests/crm/test_store_db.py``'s shape."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from delta.erp import store
from delta.persistence.database import get_tenant_session

from .conftest import db_required

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


@db_required
async def test_create_and_get_vendor_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_vendor(
            session,
            tenant_id=tenant_id,
            name="Acme Supplies",
            contact_email="orders@acme.example",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_vendor(session, vendor_id=created.vendor_id)

    assert fetched is not None
    assert fetched.name == "Acme Supplies"
    assert fetched.status == "active"


@db_required
async def test_list_vendors_ordered_newest_first(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await store.create_vendor(
            session, tenant_id=tenant_id, name="First", contact_email=None, now=_NOW
        )
        await store.create_vendor(
            session,
            tenant_id=tenant_id,
            name="Second",
            contact_email=None,
            now=_NOW + timedelta(minutes=1),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.list_vendors(session)

    assert [r.name for r in rows] == ["Second", "First"]


@db_required
async def test_asset_status_moves_forward_one_step_at_a_time(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        asset = await store.create_asset(
            session,
            tenant_id=tenant_id,
            name="Laptop",
            category="equipment",
            acquisition_cost_minor_units=150_000,
            currency="USD",
            acquired_at=None,
            assigned_team_id=None,
            now=_NOW,
        )
        await session.commit()
    assert asset.status == "active"

    # active -> disposed (skipping 'retired') is rejected: required_prior mismatch.
    async with get_tenant_session(tenant_id) as session:
        skipped = await store.try_transition_asset_status(
            session,
            asset_id=asset.asset_id,
            target_status="disposed",
            required_prior="retired",
            now=_NOW,
        )
        await session.commit()
    assert skipped is False

    # active -> retired succeeds.
    async with get_tenant_session(tenant_id) as session:
        moved = await store.try_transition_asset_status(
            session,
            asset_id=asset.asset_id,
            target_status="retired",
            required_prior="active",
            now=_NOW,
        )
        await session.commit()
    assert moved is True

    # retired -> active (backward) is rejected: required_prior mismatch (there is no
    # valid required_prior for 'active' at all, but even calling with a wrong prior
    # confirms the guard).
    async with get_tenant_session(tenant_id) as session:
        backward = await store.try_transition_asset_status(
            session,
            asset_id=asset.asset_id,
            target_status="active",
            required_prior="disposed",
            now=_NOW,
        )
        await session.commit()
    assert backward is False

    # retired -> disposed succeeds.
    async with get_tenant_session(tenant_id) as session:
        moved_again = await store.try_transition_asset_status(
            session,
            asset_id=asset.asset_id,
            target_status="disposed",
            required_prior="retired",
            now=_NOW,
        )
        await session.commit()
    assert moved_again is True

    async with get_tenant_session(tenant_id) as session:
        final = await store.get_asset(session, asset_id=asset.asset_id)
    assert final is not None
    assert final.status == "disposed"
    assert final.retired_at is not None


@db_required
async def test_asset_cost_without_currency_rejected_by_db_check(tenant_id) -> None:
    # Same value/currency pairing discipline as D-013's deals (ADR-0013 §4 finding #1),
    # applied here from the start — verify the DB CHECK backstop actually fires.
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(IntegrityError):
            await store.create_asset(
                session,
                tenant_id=tenant_id,
                name="Mismatched Asset",
                category="equipment",
                acquisition_cost_minor_units=1000,
                currency=None,
                acquired_at=None,
                assigned_team_id=None,
                now=_NOW,
            )


@db_required
async def test_purchase_order_decision_succeeds_once_then_blocked(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor = await store.create_vendor(
            session, tenant_id=tenant_id, name="Acme", contact_email=None, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        po = await store.create_purchase_order(
            session,
            tenant_id=tenant_id,
            vendor_id=vendor.vendor_id,
            asset_id=None,
            description="Office chairs",
            amount_minor_units=50_000,
            currency="USD",
            requested_by="Jane",
            now=_NOW,
        )
        await session.commit()
    assert po.status == "requested"

    async with get_tenant_session(tenant_id) as session:
        decided = await store.try_decide_purchase_order(
            session, po_id=po.po_id, new_status="approved", decided_by="Bob", now=_NOW
        )
        await session.commit()
    assert decided is True

    # A second decision attempt on an already-decided PO affects zero rows.
    async with get_tenant_session(tenant_id) as session:
        decided_again = await store.try_decide_purchase_order(
            session, po_id=po.po_id, new_status="rejected", decided_by="Bob", now=_NOW
        )
        await session.commit()
    assert decided_again is False

    async with get_tenant_session(tenant_id) as session:
        final = await store.get_purchase_order(session, po_id=po.po_id)
    assert final is not None
    assert final.status == "approved"


@db_required
async def test_cross_tenant_isolation_vendors_invisible_to_other_tenant(
    tenant_id, other_tenant_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_vendor(
            session, tenant_id=tenant_id, name="Acme", contact_email=None, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_vendor(session, vendor_id=created.vendor_id)
        listed = await store.list_vendors(session)

    assert fetched is None
    assert listed == []
