"""Invoicing orchestration (D-018, ADR-0018).

DTO <-> store mapping + the vendor/PO/milestone existence and invariant checks the
DB's FK/CHECK constraints enforce structurally at the tenant level but that still
need a friendly 4xx rather than a raw IntegrityError. Mirrors ``erp.service``: store
functions never commit, this layer commits once per mutating call.

An invoice DECISION and a recorded PAYMENT are both wired into D-009's hash-chained
audit log (``delta.persistence.audit_log.append_history``) in the SAME transaction as
the store write — mirrors D-014's identical rule for PO decisions: both are genuine
financial commitments, not business-process metadata.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..money import DEFAULT_CURRENCY
from ..persistence.audit_log import append_history
from . import store
from .schemas import (
    InvoiceCreateRequest,
    InvoiceDecisionRequest,
    InvoicePaymentView,
    InvoiceView,
    PaymentRecordRequest,
    VendorReconciliationView,
)


class VendorNotFoundError(LookupError):
    pass


class PurchaseOrderNotFoundError(LookupError):
    pass


class PurchaseOrderNotApprovedError(ValueError):
    """An invoice may only be submitted against an 'approved' purchase order."""


class PurchaseOrderVendorMismatchError(ValueError):
    """The invoice's vendor_id does not match the referenced PO's own vendor_id."""


class CurrencyMismatchError(ValueError):
    """The invoice's currency does not match the referenced PO's currency."""


class MilestoneTaskNotFoundError(LookupError):
    pass


class MilestoneTaskNotDoneError(ValueError):
    """The referenced D-015 task exists but is not (yet) 'done'."""


class InvoiceExceedsPurchaseOrderError(ValueError):
    """This invoice, plus every other non-disputed invoice already submitted against
    the same PO, would exceed the PO's own committed amount."""


class InvoiceNotFoundError(LookupError):
    pass


class InvoiceAlreadyDecidedError(RuntimeError):
    """A decision was attempted on an invoice that is no longer 'submitted'."""


class InvoiceNotPayableError(RuntimeError):
    """A payment was attempted against an invoice that is not 'approved'/'partially_paid'."""


class PaymentExceedsInvoiceBalanceError(ValueError):
    """This payment, plus every prior payment against the invoice, would exceed the
    invoice's own billed amount."""


class PaymentCurrencyMismatchError(ValueError):
    """The payment's currency does not match the invoice's own currency."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _invoice_to_view(record: store.InvoiceRecord) -> InvoiceView:
    return InvoiceView(
        invoice_id=record.invoice_id,
        tenant_id=record.tenant_id,
        vendor_id=record.vendor_id,
        po_id=record.po_id,
        milestone_task_id=record.milestone_task_id,
        invoice_number=record.invoice_number,
        description=record.description,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,  # type: ignore[arg-type]
        amount_paid_minor_units=record.amount_paid_minor_units,
        status=record.status,  # type: ignore[arg-type]
        submitted_by=record.submitted_by,
        submitted_at=record.submitted_at,
        decided_by=record.decided_by,
        decided_at=record.decided_at,
    )


def _payment_to_view(record: store.InvoicePaymentRecord) -> InvoicePaymentView:
    return InvoicePaymentView(
        payment_id=record.payment_id,
        tenant_id=record.tenant_id,
        invoice_id=record.invoice_id,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,  # type: ignore[arg-type]
        paid_at=record.paid_at,
        recorded_by=record.recorded_by,
        note=record.note,
    )


# ------------------------------------------------------------------------ invoices


async def create_invoice(session: AsyncSession, req: InvoiceCreateRequest) -> InvoiceView:
    vendor_status = await store.get_vendor_status(session, vendor_id=req.vendor_id)
    if vendor_status is None:
        raise VendorNotFoundError(req.vendor_id)

    # SELECT ... FOR UPDATE: locks the PO row for the rest of this transaction, so a
    # second concurrent invoice submission against the SAME PO blocks here until this
    # one commits or rolls back — closing the TOCTOU window a plain read before the
    # sum-check below would leave open (independent security review, ADR-0018 Fork 1
    # correction; see docs/audit/d-018-security-audit.md Finding 1, reproduced live as
    # a 10x over-commitment before this fix).
    po = await store.get_purchase_order_summary_for_update(session, po_id=req.po_id)
    if po is None:
        raise PurchaseOrderNotFoundError(req.po_id)
    if po.vendor_id != req.vendor_id:
        raise PurchaseOrderVendorMismatchError(
            f"purchase_order {req.po_id} belongs to vendor {po.vendor_id}, not {req.vendor_id}"
        )
    if po.status != "approved":
        raise PurchaseOrderNotApprovedError(
            f"purchase_order {req.po_id} is '{po.status}', not 'approved'"
        )
    if po.currency != req.currency:
        raise CurrencyMismatchError(
            f"invoice currency {req.currency} != purchase_order currency {po.currency}"
        )

    if req.milestone_task_id is not None:
        task_status = await store.get_task_status(session, task_id=req.milestone_task_id)
        if task_status is None:
            raise MilestoneTaskNotFoundError(req.milestone_task_id)
        if task_status != "done":
            raise MilestoneTaskNotDoneError(
                f"task {req.milestone_task_id} is '{task_status}', not 'done'"
            )

    already_invoiced = await store.sum_non_disputed_invoiced_for_po(session, po_id=req.po_id)
    if already_invoiced + req.amount_minor_units > po.amount_minor_units:
        raise InvoiceExceedsPurchaseOrderError(
            f"po {req.po_id}: already-invoiced {already_invoiced} + this invoice "
            f"{req.amount_minor_units} would exceed committed amount {po.amount_minor_units}"
        )

    now = _now()
    record = await store.create_invoice(
        session,
        tenant_id=req.tenant_id,
        vendor_id=req.vendor_id,
        po_id=req.po_id,
        milestone_task_id=req.milestone_task_id,
        invoice_number=req.invoice_number,
        description=req.description,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        submitted_by=req.submitted_by,
        now=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="invoice",
        entity_id=record.invoice_id,
        action="submitted",
        actor=req.submitted_by,
        now=now,
    )
    await session.commit()
    return _invoice_to_view(record)


async def list_invoice_views(
    session: AsyncSession,
    *,
    vendor_id: str | None,
    po_id: str | None,
    status: str | None,
    limit: int,
) -> list[InvoiceView]:
    records = await store.list_invoices(
        session, vendor_id=vendor_id, po_id=po_id, status=status, limit=limit
    )
    return [_invoice_to_view(r) for r in records]


async def decide_invoice(
    session: AsyncSession, *, invoice_id: str, decision: InvoiceDecisionRequest
) -> InvoiceView:
    existing = await store.get_invoice(session, invoice_id=invoice_id)
    if existing is None:
        raise InvoiceNotFoundError(invoice_id)
    new_status = "approved" if decision.action == "approve" else "disputed"
    now = _now()
    decided = await store.try_decide_invoice(
        session, invoice_id=invoice_id, new_status=new_status, decided_by=decision.actor, now=now
    )
    if not decided:
        raise InvoiceAlreadyDecidedError(invoice_id)
    await append_history(
        session,
        tenant_id=decision.tenant_id,
        entity_type="invoice",
        entity_id=invoice_id,
        action=new_status,
        actor=decision.actor,
        now=now,
        note=decision.note,
    )
    record = await store.get_invoice(session, invoice_id=invoice_id)
    await session.commit()
    if record is None:
        raise InvoiceNotFoundError(invoice_id)  # unreachable: just wrote it in this transaction
    return _invoice_to_view(record)


# ------------------------------------------------------------------------ payments


async def record_payment(
    session: AsyncSession, *, invoice_id: str, req: PaymentRecordRequest
) -> InvoicePaymentView:
    # Currency is immutable per invoice (never concurrently written), so a plain read
    # ahead of the atomic amount guard below carries no race — only the AMOUNT needs
    # the single atomic UPDATE (independent security review, ADR-0018 correction; see
    # docs/audit/d-018-security-audit.md Finding 2: a payment's currency was never
    # checked against the invoice's own currency, letting e.g. a JPY payment silently
    # settle a USD invoice and corrupt the reconciliation report's totals).
    existing = await store.get_invoice(session, invoice_id=invoice_id)
    if existing is None:
        raise InvoiceNotFoundError(invoice_id)
    if req.currency != existing.currency:
        raise PaymentCurrencyMismatchError(
            f"payment currency {req.currency} != invoice currency {existing.currency}"
        )

    now = _now()
    new_status = await store.try_record_payment(
        session, invoice_id=invoice_id, amount_minor_units=req.amount_minor_units, now=now
    )
    if new_status is None:
        current = await store.get_invoice(session, invoice_id=invoice_id)
        if current is None:
            raise InvoiceNotFoundError(invoice_id)
        if current.status not in ("approved", "partially_paid"):
            raise InvoiceNotPayableError(f"invoice {invoice_id} is '{current.status}', not payable")
        raise PaymentExceedsInvoiceBalanceError(
            f"invoice {invoice_id}: already paid {current.amount_paid_minor_units} + this "
            f"payment {req.amount_minor_units} would exceed billed amount "
            f"{current.amount_minor_units}"
        )
    payment = await store.create_invoice_payment(
        session,
        tenant_id=req.tenant_id,
        invoice_id=invoice_id,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        paid_at=req.paid_at,
        recorded_by=req.recorded_by,
        note=req.note,
        now=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="invoice_payment",
        entity_id=payment.payment_id,
        action="payment_recorded",
        actor=req.recorded_by,
        now=now,
        note=req.note,
    )
    await session.commit()
    return _payment_to_view(payment)


async def list_invoice_payment_views(
    session: AsyncSession, *, invoice_id: str, limit: int
) -> list[InvoicePaymentView]:
    records = await store.list_invoice_payments(session, invoice_id=invoice_id, limit=limit)
    return [_payment_to_view(r) for r in records]


# ------------------------------------------------------------------ reconciliation


async def get_vendor_reconciliation(
    session: AsyncSession, *, vendor_id: str, currency: str = DEFAULT_CURRENCY
) -> VendorReconciliationView:
    vendor_status = await store.get_vendor_status(session, vendor_id=vendor_id)
    if vendor_status is None:
        raise VendorNotFoundError(vendor_id)
    row = await store.compute_vendor_reconciliation(session, vendor_id=vendor_id, currency=currency)
    outstanding = row.invoiced_minor_units - row.paid_minor_units
    return VendorReconciliationView(
        vendor_id=row.vendor_id,
        currency=row.currency,  # type: ignore[arg-type]
        committed_minor_units=row.committed_minor_units,
        invoiced_minor_units=row.invoiced_minor_units,
        paid_minor_units=row.paid_minor_units,
        outstanding_minor_units=outstanding,
        disputed_invoice_count=row.disputed_invoice_count,
        over_invoiced=row.invoiced_minor_units > row.committed_minor_units,
        over_paid=row.paid_minor_units > row.invoiced_minor_units,
    )
