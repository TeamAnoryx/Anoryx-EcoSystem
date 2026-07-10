"""D-018 non-stubbed invoicing persistence suite: real store writes -> real SQL reads,
real RLS. Mirrors ``tests/erp/test_store_db.py``'s shape."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from delta.invoicing import store
from delta.persistence.database import get_tenant_session

from .conftest import db_required, seed_approved_po, seed_done_task

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


async def _create_invoice(session, *, tenant_id: str, vendor_id: str, po_id: str, amount: int):
    return await store.create_invoice(
        session,
        tenant_id=tenant_id,
        vendor_id=vendor_id,
        po_id=po_id,
        milestone_task_id=None,
        invoice_number="INV-0001",
        description="Q1 services",
        amount_minor_units=amount,
        currency="USD",
        submitted_by="ap@example.com",
        now=_NOW,
    )


@db_required
async def test_create_and_get_invoice_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        created = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=50_000
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_invoice(session, invoice_id=created.invoice_id)

    assert fetched is not None
    assert fetched.status == "submitted"
    assert fetched.amount_paid_minor_units == 0


@db_required
async def test_sum_non_disputed_invoiced_for_po_excludes_disputed(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=100_000
        )

    async with get_tenant_session(tenant_id) as session:
        kept = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=30_000
        )
        disputed = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=40_000
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        decided = await store.try_decide_invoice(
            session,
            invoice_id=disputed.invoice_id,
            new_status="disputed",
            decided_by="ap-lead@example.com",
            now=_NOW,
        )
        assert decided
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        total = await store.sum_non_disputed_invoiced_for_po(session, po_id=po_id)
    assert total == 30_000  # the disputed 40_000 is excluded
    assert kept.invoice_id != disputed.invoice_id


@db_required
async def test_try_decide_invoice_only_succeeds_once(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        first = await store.try_decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            new_status="approved",
            decided_by="a@example.com",
            now=_NOW,
        )
        await session.commit()
    assert first is True

    async with get_tenant_session(tenant_id) as session:
        second = await store.try_decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            new_status="disputed",
            decided_by="b@example.com",
            now=_NOW,
        )
        await session.commit()
    assert second is False  # already decided — the WHERE status='submitted' guard blocked it

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_invoice(session, invoice_id=invoice.invoice_id)
    assert fetched.status == "approved"  # unchanged by the failed second decision


@db_required
async def test_try_record_payment_partial_then_full(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000
        )
        decided = await store.try_decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            new_status="approved",
            decided_by="a@example.com",
            now=_NOW,
        )
        assert decided
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        status = await store.try_record_payment(
            session, invoice_id=invoice.invoice_id, amount_minor_units=4_000, now=_NOW
        )
        await session.commit()
    assert status == "partially_paid"

    async with get_tenant_session(tenant_id) as session:
        status = await store.try_record_payment(
            session, invoice_id=invoice.invoice_id, amount_minor_units=6_000, now=_NOW
        )
        await session.commit()
    assert status == "paid"

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_invoice(session, invoice_id=invoice.invoice_id)
    assert fetched.amount_paid_minor_units == 10_000
    assert fetched.status == "paid"


@db_required
async def test_try_record_payment_rejects_overpayment(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000
        )
        decided = await store.try_decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            new_status="approved",
            decided_by="a@example.com",
            now=_NOW,
        )
        assert decided
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        status = await store.try_record_payment(
            session, invoice_id=invoice.invoice_id, amount_minor_units=10_001, now=_NOW
        )
        await session.commit()
    assert status is None

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_invoice(session, invoice_id=invoice.invoice_id)
    assert fetched.amount_paid_minor_units == 0
    assert fetched.status == "approved"


@db_required
async def test_try_record_payment_rejects_when_not_payable(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000
        )
        await session.commit()  # still 'submitted' — never decided

    async with get_tenant_session(tenant_id) as session:
        status = await store.try_record_payment(
            session, invoice_id=invoice.invoice_id, amount_minor_units=1_000, now=_NOW
        )
        await session.commit()
    assert status is None


@db_required
async def test_concurrent_payments_never_overpay_invoice(tenant_id) -> None:
    """Race guard: 10 concurrent payment attempts of 2_000 each against a 10_000
    invoice — exactly 5 should succeed (summing to exactly 10_000), never more."""
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000
        )
        decided = await store.try_decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            new_status="approved",
            decided_by="a@example.com",
            now=_NOW,
        )
        assert decided
        await session.commit()

    async def _attempt() -> str | None:
        async with get_tenant_session(tenant_id) as session:
            status = await store.try_record_payment(
                session, invoice_id=invoice.invoice_id, amount_minor_units=2_000, now=_NOW
            )
            await session.commit()
            return status

    results = await asyncio.gather(*[_attempt() for _ in range(10)])
    succeeded = [r for r in results if r is not None]
    # asyncio.gather preserves input order, not commit order, so the "paid" transition
    # can land on any one of the 5 successful attempts — only its count and value set
    # are deterministic, not its position.
    assert len(succeeded) == 5
    assert succeeded.count("paid") == 1
    assert succeeded.count("partially_paid") == 4

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_invoice(session, invoice_id=invoice.invoice_id)
    assert fetched.amount_paid_minor_units == 10_000
    assert fetched.status == "paid"


@db_required
async def test_compute_vendor_reconciliation_matches_expected_totals(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=100_000
        )

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=40_000
        )
        decided = await store.try_decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            new_status="approved",
            decided_by="a@example.com",
            now=_NOW,
        )
        assert decided
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        status = await store.try_record_payment(
            session, invoice_id=invoice.invoice_id, amount_minor_units=15_000, now=_NOW
        )
        await session.commit()
    assert status == "partially_paid"

    async with get_tenant_session(tenant_id) as session:
        row = await store.compute_vendor_reconciliation(
            session, vendor_id=vendor_id, currency="USD"
        )
    assert row.committed_minor_units == 100_000
    assert row.invoiced_minor_units == 40_000
    assert row.paid_minor_units == 15_000
    assert row.disputed_invoice_count == 0


@db_required
async def test_get_task_status_returns_none_for_unknown_task(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        status = await store.get_task_status(session, task_id="does-not-exist")
    assert status is None


@db_required
async def test_get_task_status_reflects_done_task(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        task_id = await seed_done_task(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        status = await store.get_task_status(session, task_id=task_id)
    assert status == "done"


@db_required
async def test_cross_tenant_invoice_is_invisible(tenant_id, other_tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await _create_invoice(
            session, tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_invoice(session, invoice_id=invoice.invoice_id)
    assert fetched is None  # RLS: a different tenant's session cannot see this row
