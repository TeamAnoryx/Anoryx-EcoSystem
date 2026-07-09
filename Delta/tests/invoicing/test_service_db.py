"""D-018 service-layer DB tests: exception mapping, the PO/milestone/currency guards,
and the D-009 audit-chain wiring on invoice submission/decision/payment.

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as ``tests/erp/test_service_db.py``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from delta.invoicing.schemas import (
    InvoiceCreateRequest,
    InvoiceDecisionRequest,
    PaymentRecordRequest,
)
from delta.invoicing.service import (
    CurrencyMismatchError,
    InvoiceAlreadyDecidedError,
    InvoiceExceedsPurchaseOrderError,
    InvoiceNotFoundError,
    InvoiceNotPayableError,
    MilestoneTaskNotDoneError,
    MilestoneTaskNotFoundError,
    PaymentExceedsInvoiceBalanceError,
    PurchaseOrderNotApprovedError,
    PurchaseOrderNotFoundError,
    PurchaseOrderVendorMismatchError,
    VendorNotFoundError,
    create_invoice,
    decide_invoice,
    get_vendor_reconciliation,
    record_payment,
)
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_tenant_session

from .conftest import db_required, seed_approved_po, seed_done_task

_PAID_AT = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


def _invoice_req(*, tenant_id, vendor_id, po_id, amount=40_000, milestone_task_id=None, **kw):
    return InvoiceCreateRequest(
        tenant_id=tenant_id,
        vendor_id=vendor_id,
        po_id=po_id,
        milestone_task_id=milestone_task_id,
        invoice_number=kw.pop("invoice_number", "INV-0001"),
        description="Q1 services",
        amount_minor_units=amount,
        currency=kw.pop("currency", "USD"),
        submitted_by="ap@example.com",
    )


@db_required
async def test_create_invoice_against_missing_vendor_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(VendorNotFoundError):
            await create_invoice(
                session,
                _invoice_req(
                    tenant_id=tenant_id, vendor_id=str(uuid.uuid4()), po_id=str(uuid.uuid4())
                ),
            )


@db_required
async def test_create_invoice_against_missing_po_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, _po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(PurchaseOrderNotFoundError):
            await create_invoice(
                session,
                _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=str(uuid.uuid4())),
            )


@db_required
async def test_create_invoice_vendor_mismatch_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        _vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)
    async with get_tenant_session(tenant_id) as session:
        other_vendor_id, _other_po = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(PurchaseOrderVendorMismatchError):
            await create_invoice(
                session,
                _invoice_req(tenant_id=tenant_id, vendor_id=other_vendor_id, po_id=po_id),
            )


@db_required
async def test_create_invoice_against_unapproved_po_raises(tenant_id) -> None:
    from delta.erp import store as erp_store

    now = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as session:
        vendor = await erp_store.create_vendor(
            session, tenant_id=tenant_id, name="Acme", contact_email=None, now=now
        )
        po = await erp_store.create_purchase_order(
            session,
            tenant_id=tenant_id,
            vendor_id=vendor.vendor_id,
            asset_id=None,
            description="pending",
            amount_minor_units=10_000,
            currency="USD",
            requested_by="buyer@example.com",
            now=now,
        )
        await session.commit()  # PO stays 'requested' — never decided

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(PurchaseOrderNotApprovedError):
            await create_invoice(
                session,
                _invoice_req(tenant_id=tenant_id, vendor_id=vendor.vendor_id, po_id=po.po_id),
            )


@db_required
async def test_create_invoice_currency_mismatch_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id, currency="USD")

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(CurrencyMismatchError):
            await create_invoice(
                session,
                _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, currency="EUR"),
            )


@db_required
async def test_create_invoice_with_missing_milestone_task_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(MilestoneTaskNotFoundError):
            await create_invoice(
                session,
                _invoice_req(
                    tenant_id=tenant_id,
                    vendor_id=vendor_id,
                    po_id=po_id,
                    milestone_task_id=str(uuid.uuid4()),
                ),
            )


@db_required
async def test_create_invoice_with_undone_milestone_task_raises(tenant_id) -> None:
    from delta.pm import store as pm_store

    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)
    async with get_tenant_session(tenant_id) as session:
        task = await pm_store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=str(uuid.uuid4()),
            sprint_id=None,
            title="In progress",
            story_points=2,
            assignee=None,
            now=datetime.now(timezone.utc),
        )
        await session.commit()  # task stays 'todo' — never marked done

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(MilestoneTaskNotDoneError):
            await create_invoice(
                session,
                _invoice_req(
                    tenant_id=tenant_id,
                    vendor_id=vendor_id,
                    po_id=po_id,
                    milestone_task_id=task.task_id,
                ),
            )


@db_required
async def test_create_invoice_with_done_milestone_task_succeeds(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)
    async with get_tenant_session(tenant_id) as session:
        task_id = await seed_done_task(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session,
            _invoice_req(
                tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, milestone_task_id=task_id
            ),
        )
    assert invoice.milestone_task_id == task_id
    assert invoice.status == "submitted"


@db_required
async def test_create_invoice_exceeding_po_amount_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=50_000
        )

    async with get_tenant_session(tenant_id) as session:
        await create_invoice(
            session,
            _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=40_000),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(InvoiceExceedsPurchaseOrderError):
            await create_invoice(
                session,
                _invoice_req(
                    tenant_id=tenant_id,
                    vendor_id=vendor_id,
                    po_id=po_id,
                    amount=20_000,
                    invoice_number="INV-0002",
                ),
            )


@db_required
async def test_create_invoice_submission_is_audited(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session, _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id)
        )

    async with get_tenant_session(tenant_id) as session:
        history = await list_history(session, entity_type="invoice", entity_id=invoice.invoice_id)
    assert len(history) == 1
    assert history[0].action == "submitted"


@db_required
async def test_decide_invoice_twice_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session, _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id)
        )

    async with get_tenant_session(tenant_id) as session:
        decided = await decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            decision=InvoiceDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="lead@example.com"
            ),
        )
    assert decided.status == "approved"

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(InvoiceAlreadyDecidedError):
            await decide_invoice(
                session,
                invoice_id=invoice.invoice_id,
                decision=InvoiceDecisionRequest(
                    tenant_id=tenant_id, action="dispute", actor="lead@example.com"
                ),
            )


@db_required
async def test_record_payment_against_missing_invoice_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(InvoiceNotFoundError):
            await record_payment(
                session,
                invoice_id=str(uuid.uuid4()),
                req=PaymentRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=1_000,
                    paid_at=_PAID_AT,
                    recorded_by="treasury@example.com",
                ),
            )


@db_required
async def test_record_payment_against_unapproved_invoice_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session, _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id)
        )  # still 'submitted' — never decided

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(InvoiceNotPayableError):
            await record_payment(
                session,
                invoice_id=invoice.invoice_id,
                req=PaymentRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=1_000,
                    paid_at=_PAID_AT,
                    recorded_by="treasury@example.com",
                ),
            )


@db_required
async def test_record_payment_exceeding_balance_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session,
            _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000),
        )

    async with get_tenant_session(tenant_id) as session:
        await decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            decision=InvoiceDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="lead@example.com"
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(PaymentExceedsInvoiceBalanceError):
            await record_payment(
                session,
                invoice_id=invoice.invoice_id,
                req=PaymentRecordRequest(
                    tenant_id=tenant_id,
                    amount_minor_units=10_001,
                    paid_at=_PAID_AT,
                    recorded_by="treasury@example.com",
                ),
            )


@db_required
async def test_record_payment_is_audited(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(session, tenant_id=tenant_id)

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session,
            _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=10_000),
        )

    async with get_tenant_session(tenant_id) as session:
        await decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            decision=InvoiceDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="lead@example.com"
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        payment = await record_payment(
            session,
            invoice_id=invoice.invoice_id,
            req=PaymentRecordRequest(
                tenant_id=tenant_id,
                amount_minor_units=10_000,
                paid_at=_PAID_AT,
                recorded_by="treasury@example.com",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        history = await list_history(
            session, entity_type="invoice_payment", entity_id=payment.payment_id
        )
    assert len(history) == 1
    assert history[0].action == "payment_recorded"


@db_required
async def test_reconciliation_against_missing_vendor_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(VendorNotFoundError):
            await get_vendor_reconciliation(session, vendor_id=str(uuid.uuid4()))


@db_required
async def test_reconciliation_reflects_committed_invoiced_paid(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor_id, po_id = await seed_approved_po(
            session, tenant_id=tenant_id, amount_minor_units=100_000
        )

    async with get_tenant_session(tenant_id) as session:
        invoice = await create_invoice(
            session,
            _invoice_req(tenant_id=tenant_id, vendor_id=vendor_id, po_id=po_id, amount=60_000),
        )

    async with get_tenant_session(tenant_id) as session:
        await decide_invoice(
            session,
            invoice_id=invoice.invoice_id,
            decision=InvoiceDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="lead@example.com"
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        await record_payment(
            session,
            invoice_id=invoice.invoice_id,
            req=PaymentRecordRequest(
                tenant_id=tenant_id,
                amount_minor_units=20_000,
                paid_at=_PAID_AT,
                recorded_by="treasury@example.com",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        report = await get_vendor_reconciliation(session, vendor_id=vendor_id)
    assert report.committed_minor_units == 100_000
    assert report.invoiced_minor_units == 60_000
    assert report.paid_minor_units == 20_000
    assert report.outstanding_minor_units == 40_000
    assert report.over_invoiced is False
    assert report.over_paid is False
    assert report.disputed_invoice_count == 0
