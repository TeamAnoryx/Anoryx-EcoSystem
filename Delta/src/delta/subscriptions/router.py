"""Subscriptions HTTP surface: ``/v1/admin/subscriptions/*`` (D-022).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/D-008/D-012/D-014 all use.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from ..allocation_admin.auth import require_admin
from ..identifiers import SubscriptionId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_BASELINE_WINDOW as _DEFAULT_BASELINE_WINDOW
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    ChargeRecordRequest,
    ChargeView,
    SubscriptionAnomalyQuery,
    SubscriptionAnomalyReportView,
    SubscriptionCancelRequest,
    SubscriptionCreateRequest,
    SubscriptionStatus,
    SubscriptionView,
)
from .service import (
    SubscriptionAlreadyCancelledError,
    SubscriptionNotFoundError,
    VendorNotFoundError,
)

router = APIRouter(prefix="/v1/admin/subscriptions", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


def _query_error(exc: ValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.post("", status_code=201, response_model=SubscriptionView)
async def post_subscription(req: SubscriptionCreateRequest) -> SubscriptionView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_subscription(session, req)
        except VendorNotFoundError as exc:
            raise _not_found("vendor_not_found") from exc


@router.get("", response_model=list[SubscriptionView])
async def get_subscriptions(
    tenant_id: TenantId,
    status: SubscriptionStatus | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[SubscriptionView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_subscription_views(session, status=status, limit=limit)


@router.post("/{subscription_id}/cancel", response_model=SubscriptionView)
async def post_subscription_cancel(
    subscription_id: SubscriptionId, req: SubscriptionCancelRequest
) -> SubscriptionView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.cancel_subscription(
                session, subscription_id=subscription_id, req=req
            )
        except SubscriptionNotFoundError as exc:
            raise _not_found("subscription_not_found") from exc
        except SubscriptionAlreadyCancelledError as exc:
            raise HTTPException(status_code=409, detail="subscription_already_cancelled") from exc


@router.post("/{subscription_id}/charges", status_code=201, response_model=ChargeView)
async def post_subscription_charge(
    subscription_id: SubscriptionId, req: ChargeRecordRequest
) -> ChargeView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.record_charge(session, subscription_id=subscription_id, req=req)
        except SubscriptionNotFoundError as exc:
            raise _not_found("subscription_not_found") from exc


@router.get("/{subscription_id}/charges", response_model=list[ChargeView])
async def get_subscription_charges(
    subscription_id: SubscriptionId, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[ChargeView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_charge_views(
            session, subscription_id=subscription_id, limit=limit
        )


@router.get("/anomalies", response_model=SubscriptionAnomalyReportView)
async def get_subscription_anomalies(
    tenant_id: TenantId, baseline_window: int = _DEFAULT_BASELINE_WINDOW
) -> SubscriptionAnomalyReportView:
    try:
        query = SubscriptionAnomalyQuery(tenant_id=tenant_id, baseline_window=baseline_window)
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await service.get_anomaly_report(session, query)
