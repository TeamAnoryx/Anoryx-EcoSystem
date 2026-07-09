"""ERP HTTP surface: ``/v1/admin/erp/*`` (D-014).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/D-008/D-011/D-012/D-013 all use.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import AssetId, PurchaseOrderId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    AssetCreateRequest,
    AssetStatusTransitionRequest,
    AssetView,
    PurchaseOrderCreateRequest,
    PurchaseOrderDecisionRequest,
    PurchaseOrderStatus,
    PurchaseOrderView,
    VendorCreateRequest,
    VendorView,
)
from .service import (
    AssetNotFoundError,
    InvalidAssetTransitionError,
    PurchaseOrderAlreadyDecidedError,
    PurchaseOrderNotFoundError,
    VendorNotFoundError,
)

router = APIRouter(prefix="/v1/admin/erp", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


# ------------------------------------------------------------------------- vendors


@router.post("/vendors", status_code=201, response_model=VendorView)
async def post_vendor(req: VendorCreateRequest) -> VendorView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_vendor(session, req)


@router.get("/vendors", response_model=list[VendorView])
async def get_vendors(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[VendorView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_vendor_views(session, limit=limit)


# -------------------------------------------------------------------------- assets


@router.post("/assets", status_code=201, response_model=AssetView)
async def post_asset(req: AssetCreateRequest) -> AssetView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_asset(session, req)


@router.get("/assets", response_model=list[AssetView])
async def get_assets(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[AssetView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_asset_views(session, limit=limit)


@router.post("/assets/{asset_id}/status", response_model=AssetView)
async def post_asset_status(asset_id: AssetId, req: AssetStatusTransitionRequest) -> AssetView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.transition_asset_status(session, asset_id=asset_id, req=req)
        except AssetNotFoundError as exc:
            raise _not_found("asset_not_found") from exc
        except InvalidAssetTransitionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


# ------------------------------------------------------------------ purchase_orders


@router.post("/purchase-orders", status_code=201, response_model=PurchaseOrderView)
async def post_purchase_order(req: PurchaseOrderCreateRequest) -> PurchaseOrderView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_purchase_order(session, req)
        except VendorNotFoundError as exc:
            raise _not_found("vendor_not_found") from exc
        except AssetNotFoundError as exc:
            raise _not_found("asset_not_found") from exc


@router.get("/purchase-orders", response_model=list[PurchaseOrderView])
async def get_purchase_orders(
    tenant_id: TenantId,
    status: PurchaseOrderStatus | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[PurchaseOrderView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_purchase_order_views(session, status=status, limit=limit)


@router.post("/purchase-orders/{po_id}/decision", response_model=PurchaseOrderView)
async def post_purchase_order_decision(
    po_id: PurchaseOrderId, decision: PurchaseOrderDecisionRequest
) -> PurchaseOrderView:
    async with get_tenant_session(decision.tenant_id) as session:
        try:
            return await service.decide_purchase_order(session, po_id=po_id, decision=decision)
        except PurchaseOrderNotFoundError as exc:
            raise _not_found("purchase_order_not_found") from exc
        except PurchaseOrderAlreadyDecidedError as exc:
            raise HTTPException(status_code=409, detail="purchase_order_already_decided") from exc
