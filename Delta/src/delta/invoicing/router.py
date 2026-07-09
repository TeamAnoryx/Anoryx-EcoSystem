"""Invoicing HTTP surface: ``/v1/admin/invoicing/*`` (D-018).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/D-008/D-011/.../D-014 all use.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route — mirrors every other admin surface except D-017's dashboards (this task
does not retrofit RBAC onto a new surface; see docs/adr/0018-delta-invoicing-
reconciliation.md §3).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import InvoiceId, PurchaseOrderId, TenantId, VendorId
from ..money import DEFAULT_CURRENCY
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    InvoiceCreateRequest,
    InvoiceDecisionRequest,
    InvoicePaymentView,
    InvoiceStatus,
    InvoiceView,
    PaymentRecordRequest,
    VendorReconciliationView,
)
from .service import (
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
)

router = APIRouter(prefix="/v1/admin/invoicing", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=409, detail=detail)


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(status_code=422, detail=detail)


# ------------------------------------------------------------------------ invoices


@router.post("/invoices", status_code=201, response_model=InvoiceView)
async def post_invoice(req: InvoiceCreateRequest) -> InvoiceView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_invoice(session, req)
        except VendorNotFoundError as exc:
            raise _not_found("vendor_not_found") from exc
        except PurchaseOrderNotFoundError as exc:
            raise _not_found("purchase_order_not_found") from exc
        except MilestoneTaskNotFoundError as exc:
            raise _not_found("milestone_task_not_found") from exc
        except (
            PurchaseOrderVendorMismatchError,
            PurchaseOrderNotApprovedError,
            CurrencyMismatchError,
            MilestoneTaskNotDoneError,
            InvoiceExceedsPurchaseOrderError,
        ) as exc:
            raise _unprocessable(str(exc)) from exc


@router.get("/invoices", response_model=list[InvoiceView])
async def get_invoices(
    tenant_id: TenantId,
    vendor_id: VendorId | None = None,
    po_id: PurchaseOrderId | None = None,
    status: InvoiceStatus | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[InvoiceView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_invoice_views(
            session, vendor_id=vendor_id, po_id=po_id, status=status, limit=limit
        )


@router.post("/invoices/{invoice_id}/decision", response_model=InvoiceView)
async def post_invoice_decision(
    invoice_id: InvoiceId, decision: InvoiceDecisionRequest
) -> InvoiceView:
    async with get_tenant_session(decision.tenant_id) as session:
        try:
            return await service.decide_invoice(session, invoice_id=invoice_id, decision=decision)
        except InvoiceNotFoundError as exc:
            raise _not_found("invoice_not_found") from exc
        except InvoiceAlreadyDecidedError as exc:
            raise _conflict("invoice_already_decided") from exc


# ------------------------------------------------------------------------ payments


@router.post("/invoices/{invoice_id}/payments", status_code=201, response_model=InvoicePaymentView)
async def post_invoice_payment(
    invoice_id: InvoiceId, req: PaymentRecordRequest
) -> InvoicePaymentView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.record_payment(session, invoice_id=invoice_id, req=req)
        except InvoiceNotFoundError as exc:
            raise _not_found("invoice_not_found") from exc
        except InvoiceNotPayableError as exc:
            raise _conflict(str(exc)) from exc
        except PaymentExceedsInvoiceBalanceError as exc:
            raise _unprocessable(str(exc)) from exc


@router.get("/invoices/{invoice_id}/payments", response_model=list[InvoicePaymentView])
async def get_invoice_payments(
    invoice_id: InvoiceId, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[InvoicePaymentView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_invoice_payment_views(session, invoice_id=invoice_id, limit=limit)


# ------------------------------------------------------------------ reconciliation


@router.get("/reconciliation", response_model=VendorReconciliationView)
async def get_reconciliation(
    tenant_id: TenantId, vendor_id: VendorId, currency: str = DEFAULT_CURRENCY
) -> VendorReconciliationView:
    async with get_tenant_session(tenant_id) as session:
        try:
            return await service.get_vendor_reconciliation(
                session, vendor_id=vendor_id, currency=currency
            )
        except VendorNotFoundError as exc:
            raise _not_found("vendor_not_found") from exc
