"""Corporate ERP/procurement/cloud-cost sync HTTP surface:
``/v1/admin/integrations/*`` (D-019).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/D-008/.../D-018 all use. ``require_admin``
gates every route — mirrors every other admin surface except D-017's dashboards (this
task does not retrofit RBAC onto a new surface; see docs/adr/0019-delta-erp-
integrations.md §3).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import ExternalSystemId, SyncRunId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    ExternalSystemCreateRequest,
    ExternalSystemView,
    SyncLineItemView,
    SyncRunCreateRequest,
    SyncRunView,
    SystemReconciliationView,
)
from .service import SystemDisabledError, SystemNotFoundError

router = APIRouter(prefix="/v1/admin/integrations", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=409, detail=detail)


# ------------------------------------------------------------------ external_systems


@router.post("/systems", status_code=201, response_model=ExternalSystemView)
async def post_system(req: ExternalSystemCreateRequest) -> ExternalSystemView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_external_system(session, req)


@router.get("/systems", response_model=list[ExternalSystemView])
async def get_systems(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[ExternalSystemView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_external_system_views(session, limit=limit)


# ------------------------------------------------------------------------ sync_runs


@router.post("/systems/{system_id}/sync", status_code=201, response_model=SyncRunView)
async def post_sync(system_id: ExternalSystemId, req: SyncRunCreateRequest) -> SyncRunView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.run_sync(session, system_id=system_id, req=req)
        except SystemNotFoundError as exc:
            raise _not_found("external_system_not_found") from exc
        except SystemDisabledError as exc:
            raise _conflict(str(exc)) from exc


@router.get("/systems/{system_id}/sync-runs", response_model=list[SyncRunView])
async def get_sync_runs(
    system_id: ExternalSystemId, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[SyncRunView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_sync_run_views(session, system_id=system_id, limit=limit)


@router.get("/sync-runs/{sync_run_id}/line-items", response_model=list[SyncLineItemView])
async def get_sync_line_items(
    sync_run_id: SyncRunId, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[SyncLineItemView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_sync_line_item_views(
            session, sync_run_id=sync_run_id, limit=limit
        )


# ------------------------------------------------------------------ reconciliation


@router.get("/systems/{system_id}/reconciliation", response_model=SystemReconciliationView)
async def get_reconciliation(
    system_id: ExternalSystemId, tenant_id: TenantId
) -> SystemReconciliationView:
    async with get_tenant_session(tenant_id) as session:
        try:
            return await service.get_system_reconciliation(session, system_id=system_id)
        except SystemNotFoundError as exc:
            raise _not_found("external_system_not_found") from exc
