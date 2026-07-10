"""Invoicing persistence (D-018, ADR-0018).

Tenant-scoped reads/writes against ``invoices``/``invoice_payments`` (migration
0012). Every function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like ``erp.store``/``pm.store``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import case, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import invoice_payments, invoices, purchase_orders, tasks, vendors

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# An invoice is billable against a PO only once it has been decided 'approved' — the
# same commitment gate D-014's own PO->decision workflow enforces before any spend.
_INVOICEABLE_PO_STATUS = "approved"

# Statuses that still count toward "invoiced" for reconciliation purposes — everything
# except 'disputed' (a disputed invoice's claim is contested, not a real commitment).
_NON_DISPUTED_INVOICE_STATUSES = ("submitted", "approved", "partially_paid", "paid")

# Statuses a payment may be recorded against.
_PAYABLE_INVOICE_STATUSES = ("approved", "partially_paid")


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class InvoiceRecord:
    invoice_id: str
    tenant_id: str
    vendor_id: str
    po_id: str
    milestone_task_id: str | None
    invoice_number: str
    description: str
    amount_minor_units: int
    currency: str
    amount_paid_minor_units: int
    status: str
    submitted_by: str
    submitted_at: datetime
    decided_by: str | None
    decided_at: datetime | None


@dataclass(frozen=True)
class InvoicePaymentRecord:
    payment_id: str
    tenant_id: str
    invoice_id: str
    amount_minor_units: int
    currency: str
    paid_at: datetime
    recorded_by: str
    note: str | None


def _invoice_from_row(row) -> InvoiceRecord:
    return InvoiceRecord(
        invoice_id=row.invoice_id,
        tenant_id=row.tenant_id,
        vendor_id=row.vendor_id,
        po_id=row.po_id,
        milestone_task_id=row.milestone_task_id,
        invoice_number=row.invoice_number,
        description=row.description,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        amount_paid_minor_units=row.amount_paid_minor_units,
        status=row.status,
        submitted_by=row.submitted_by,
        submitted_at=row.submitted_at,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
    )


def _payment_from_row(row) -> InvoicePaymentRecord:
    return InvoicePaymentRecord(
        payment_id=row.payment_id,
        tenant_id=row.tenant_id,
        invoice_id=row.invoice_id,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        paid_at=row.paid_at,
        recorded_by=row.recorded_by,
        note=row.note,
    )


# ------------------------------------------------------------------------ invoices


async def create_invoice(
    session: AsyncSession,
    *,
    tenant_id: str,
    vendor_id: str,
    po_id: str,
    milestone_task_id: str | None,
    invoice_number: str,
    description: str,
    amount_minor_units: int,
    currency: str,
    submitted_by: str,
    now: datetime,
    invoice_id: str | None = None,
) -> InvoiceRecord:
    iid = invoice_id or str(uuid.uuid4())
    await session.execute(
        insert(invoices).values(
            invoice_id=iid,
            tenant_id=tenant_id,
            vendor_id=vendor_id,
            po_id=po_id,
            milestone_task_id=milestone_task_id,
            invoice_number=invoice_number,
            description=description,
            amount_minor_units=amount_minor_units,
            currency=currency,
            amount_paid_minor_units=0,
            status="submitted",
            submitted_by=submitted_by,
            submitted_at=now,
            decided_by=None,
            decided_at=None,
            created_at=now,
            updated_at=now,
        )
    )
    return InvoiceRecord(
        invoice_id=iid,
        tenant_id=tenant_id,
        vendor_id=vendor_id,
        po_id=po_id,
        milestone_task_id=milestone_task_id,
        invoice_number=invoice_number,
        description=description,
        amount_minor_units=amount_minor_units,
        currency=currency,
        amount_paid_minor_units=0,
        status="submitted",
        submitted_by=submitted_by,
        submitted_at=now,
        decided_by=None,
        decided_at=None,
    )


async def get_invoice(session: AsyncSession, *, invoice_id: str) -> InvoiceRecord | None:
    row = (
        await session.execute(select(invoices).where(invoices.c.invoice_id == invoice_id))
    ).first()
    return None if row is None else _invoice_from_row(row)


async def list_invoices(
    session: AsyncSession,
    *,
    vendor_id: str | None = None,
    po_id: str | None = None,
    status: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[InvoiceRecord]:
    stmt = select(invoices)
    if vendor_id is not None:
        stmt = stmt.where(invoices.c.vendor_id == vendor_id)
    if po_id is not None:
        stmt = stmt.where(invoices.c.po_id == po_id)
    if status is not None:
        stmt = stmt.where(invoices.c.status == status)
    stmt = stmt.order_by(invoices.c.submitted_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_invoice_from_row(r) for r in rows]


async def sum_non_disputed_invoiced_for_po(session: AsyncSession, *, po_id: str) -> int:
    """Sum of ``amount_minor_units`` for every non-disputed invoice already submitted
    against ``po_id`` — the over-invoicing guard's input (ADR-0018 Fork 1)."""
    stmt = select(func.coalesce(func.sum(invoices.c.amount_minor_units), 0)).where(
        invoices.c.po_id == po_id, invoices.c.status.in_(_NON_DISPUTED_INVOICE_STATUSES)
    )
    return (await session.execute(stmt)).scalar_one()


async def try_decide_invoice(
    session: AsyncSession,
    *,
    invoice_id: str,
    new_status: str,
    decided_by: str,
    now: datetime,
) -> bool:
    """Conditionally transition 'submitted' -> ``new_status``. Does NOT commit.

    Guards concurrent double-decision — identical shape to D-014's
    ``try_decide_purchase_order``: the WHERE clause only matches a row still
    'submitted'. Returns True iff this call performed the transition.
    """
    result = await session.execute(
        update(invoices)
        .where(invoices.c.invoice_id == invoice_id)
        .where(invoices.c.status == "submitted")
        .values(status=new_status, decided_by=decided_by, decided_at=now, updated_at=now)
    )
    return result.rowcount == 1


async def try_record_payment(
    session: AsyncSession,
    *,
    invoice_id: str,
    amount_minor_units: int,
    now: datetime,
) -> str | None:
    """Conditionally increment ``amount_paid_minor_units`` and roll the invoice's
    status forward to 'partially_paid' or 'paid'. Does NOT commit.

    A SINGLE atomic UPDATE with a computed WHERE guard
    (``amount_paid_minor_units + :amount <= amount_minor_units``) — race-safe against
    concurrent payment recordings the same way D-005's budget engine guards a spend
    increment: two concurrent callers can never together overpay a single invoice,
    because only one UPDATE can match the (soon-to-be-stale) pre-increment row at a
    time under Postgres's row-level locking, and the second retries against the
    already-updated total. Returns the new status string iff this call performed the
    update, else ``None`` (the invoice was not payable, or this payment would have
    overpaid it).
    """
    new_status_case = (
        invoices.c.amount_paid_minor_units + amount_minor_units == invoices.c.amount_minor_units
    )
    result = await session.execute(
        update(invoices)
        .where(invoices.c.invoice_id == invoice_id)
        .where(invoices.c.status.in_(_PAYABLE_INVOICE_STATUSES))
        .where(
            invoices.c.amount_paid_minor_units + amount_minor_units <= invoices.c.amount_minor_units
        )
        .values(
            amount_paid_minor_units=invoices.c.amount_paid_minor_units + amount_minor_units,
            status=case((new_status_case, "paid"), else_="partially_paid"),
            updated_at=now,
        )
        .returning(invoices.c.status)
    )
    row = result.first()
    return None if row is None else row[0]


async def create_invoice_payment(
    session: AsyncSession,
    *,
    tenant_id: str,
    invoice_id: str,
    amount_minor_units: int,
    currency: str,
    paid_at: datetime,
    recorded_by: str,
    note: str | None,
    now: datetime,
    payment_id: str | None = None,
) -> InvoicePaymentRecord:
    pid = payment_id or str(uuid.uuid4())
    await session.execute(
        insert(invoice_payments).values(
            payment_id=pid,
            tenant_id=tenant_id,
            invoice_id=invoice_id,
            amount_minor_units=amount_minor_units,
            currency=currency,
            paid_at=paid_at,
            recorded_by=recorded_by,
            note=note,
            created_at=now,
        )
    )
    return InvoicePaymentRecord(
        payment_id=pid,
        tenant_id=tenant_id,
        invoice_id=invoice_id,
        amount_minor_units=amount_minor_units,
        currency=currency,
        paid_at=paid_at,
        recorded_by=recorded_by,
        note=note,
    )


async def list_invoice_payments(
    session: AsyncSession, *, invoice_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[InvoicePaymentRecord]:
    stmt = (
        select(invoice_payments)
        .where(invoice_payments.c.invoice_id == invoice_id)
        .order_by(invoice_payments.c.paid_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_payment_from_row(r) for r in rows]


# --------------------------------------------------------- cross-table validation
# Reads the shared `vendors`/`purchase_orders`/`tasks` tables directly rather than
# importing `erp.store`/`pm.store` — mirrors D-016's `capacity.store` precedent of
# querying another task's table (`tasks`) via `persistence.models` directly instead
# of cross-importing its owning package's store module.


@dataclass(frozen=True)
class PurchaseOrderSummary:
    po_id: str
    vendor_id: str
    status: str
    amount_minor_units: int
    currency: str


async def get_vendor_status(session: AsyncSession, *, vendor_id: str) -> str | None:
    row = (
        await session.execute(select(vendors.c.status).where(vendors.c.vendor_id == vendor_id))
    ).first()
    return None if row is None else row[0]


async def get_purchase_order_summary(
    session: AsyncSession, *, po_id: str
) -> PurchaseOrderSummary | None:
    row = (
        await session.execute(
            select(
                purchase_orders.c.po_id,
                purchase_orders.c.vendor_id,
                purchase_orders.c.status,
                purchase_orders.c.amount_minor_units,
                purchase_orders.c.currency,
            ).where(purchase_orders.c.po_id == po_id)
        )
    ).first()
    return (
        None
        if row is None
        else PurchaseOrderSummary(
            po_id=row.po_id,
            vendor_id=row.vendor_id,
            status=row.status,
            amount_minor_units=row.amount_minor_units,
            currency=row.currency,
        )
    )


async def get_purchase_order_summary_for_update(
    session: AsyncSession, *, po_id: str
) -> PurchaseOrderSummary | None:
    """Same as :func:`get_purchase_order_summary`, but takes a ``SELECT ... FOR UPDATE``
    row lock on the PO. MUST be used (not the plain read) by any caller that goes on to
    sum-and-compare against this PO's invoices before inserting a new one — the lock
    serializes concurrent invoice submissions against the SAME PO so the second
    transaction's sum-check only proceeds once the first has committed (or rolled
    back), closing the TOCTOU window a plain read-then-insert would leave open
    (independent security review, ADR-0018 Fork 1 correction — see
    docs/audit/d-018-security-audit.md Finding 1). Submissions against DIFFERENT POs
    are unaffected (distinct rows, no contention).
    """
    row = (
        await session.execute(
            select(
                purchase_orders.c.po_id,
                purchase_orders.c.vendor_id,
                purchase_orders.c.status,
                purchase_orders.c.amount_minor_units,
                purchase_orders.c.currency,
            )
            .where(purchase_orders.c.po_id == po_id)
            .with_for_update()
        )
    ).first()
    return (
        None
        if row is None
        else PurchaseOrderSummary(
            po_id=row.po_id,
            vendor_id=row.vendor_id,
            status=row.status,
            amount_minor_units=row.amount_minor_units,
            currency=row.currency,
        )
    )


async def get_task_status(session: AsyncSession, *, task_id: str) -> str | None:
    row = (await session.execute(select(tasks.c.status).where(tasks.c.task_id == task_id))).first()
    return None if row is None else row[0]


# ------------------------------------------------------------------ reconciliation


@dataclass(frozen=True)
class VendorReconciliationRow:
    vendor_id: str
    currency: str
    committed_minor_units: int
    invoiced_minor_units: int
    paid_minor_units: int
    disputed_invoice_count: int


async def compute_vendor_reconciliation(
    session: AsyncSession, *, vendor_id: str, currency: str
) -> VendorReconciliationRow:
    """Sum committed (approved PO totals), invoiced (non-disputed invoice totals), and
    paid amounts for one vendor, scoped to one currency (D-001's no-FX rule — mixing
    currencies in one sum would be meaningless, mirrors
    ``delta.reconciliation.reconcile_allocation``'s own single-currency guard).
    """
    committed_stmt = select(func.coalesce(func.sum(purchase_orders.c.amount_minor_units), 0)).where(
        purchase_orders.c.vendor_id == vendor_id,
        purchase_orders.c.status == _INVOICEABLE_PO_STATUS,
        purchase_orders.c.currency == currency,
    )
    invoiced_stmt = select(func.coalesce(func.sum(invoices.c.amount_minor_units), 0)).where(
        invoices.c.vendor_id == vendor_id,
        invoices.c.status.in_(_NON_DISPUTED_INVOICE_STATUSES),
        invoices.c.currency == currency,
    )
    paid_stmt = select(func.coalesce(func.sum(invoices.c.amount_paid_minor_units), 0)).where(
        invoices.c.vendor_id == vendor_id,
        invoices.c.currency == currency,
    )
    disputed_count_stmt = select(func.count()).where(
        invoices.c.vendor_id == vendor_id,
        invoices.c.status == "disputed",
        invoices.c.currency == currency,
    )
    committed = (await session.execute(committed_stmt)).scalar_one()
    invoiced = (await session.execute(invoiced_stmt)).scalar_one()
    paid = (await session.execute(paid_stmt)).scalar_one()
    disputed_count = (await session.execute(disputed_count_stmt)).scalar_one()
    return VendorReconciliationRow(
        vendor_id=vendor_id,
        currency=currency,
        committed_minor_units=committed,
        invoiced_minor_units=invoiced,
        paid_minor_units=paid,
        disputed_invoice_count=disputed_count,
    )
