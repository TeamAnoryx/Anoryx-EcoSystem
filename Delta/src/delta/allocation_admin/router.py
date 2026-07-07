"""Allocation-admin HTTP surface: ``POST/GET /v1/admin/allocations``,
``POST /v1/admin/allocations/{id}/decision``, ``GET /v1/admin/history`` (D-007).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` for
the ``tenant_id`` the caller supplies (query param on GET, body field on POST) — the
admin operator explicitly targets one tenant per call, the same "per-target session"
shape as Sentinel's F-012a admin API. ``require_admin`` gates every route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..identifiers import TenantId
from ..persistence.database import get_tenant_session
from .auth import require_admin
from .schemas import (
    AllocationCreateRequest,
    AllocationStatus,
    AllocationView,
    ApprovalDecisionRequest,
    ChangeHistoryEntryView,
)
from .service import (
    AllocationAlreadyDecidedError,
    AllocationNotFoundError,
    AllocationReconciliationError,
    create_allocation_request,
    decide_allocation,
    get_allocation_view,
    list_allocation_views,
)
from .store import list_history

router = APIRouter(prefix="/v1/admin", dependencies=[Depends(require_admin)])


@router.post("/allocations", status_code=201, response_model=AllocationView)
async def post_allocation(req: AllocationCreateRequest) -> AllocationView:
    try:
        async with get_tenant_session(req.tenant_id) as session:
            return await create_allocation_request(session, req)
    except AllocationReconciliationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/allocations", response_model=list[AllocationView])
async def get_allocations(
    tenant_id: TenantId,
    status: AllocationStatus | None = None,
    limit: int = 100,
) -> list[AllocationView]:
    # list_allocation_views/store.list_allocations clamp limit server-side
    # regardless of what's passed here — this is not the enforcement boundary.
    async with get_tenant_session(tenant_id) as session:
        return await list_allocation_views(session, status=status, limit=limit)


@router.get("/allocations/{allocation_id}", response_model=AllocationView)
async def get_allocation(allocation_id: str, tenant_id: TenantId) -> AllocationView:
    async with get_tenant_session(tenant_id) as session:
        view = await get_allocation_view(session, allocation_id=allocation_id)
    if view is None or view.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="allocation_not_found")
    return view


@router.post("/allocations/{allocation_id}/decision", response_model=AllocationView)
async def post_decision(allocation_id: str, decision: ApprovalDecisionRequest) -> AllocationView:
    try:
        async with get_tenant_session(decision.tenant_id) as session:
            return await decide_allocation(session, allocation_id=allocation_id, decision=decision)
    except AllocationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="allocation_not_found") from exc
    except AllocationAlreadyDecidedError as exc:
        raise HTTPException(status_code=409, detail="allocation_already_decided") from exc


@router.get("/history", response_model=list[ChangeHistoryEntryView])
async def get_history(
    tenant_id: TenantId,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 100,
) -> list[ChangeHistoryEntryView]:
    async with get_tenant_session(tenant_id) as session:
        rows = await list_history(
            session, entity_type=entity_type, entity_id=entity_id, limit=limit
        )
    return [
        ChangeHistoryEntryView(
            history_id=r.history_id,
            tenant_id=r.tenant_id,
            entity_type=r.entity_type,
            entity_id=r.entity_id,
            action=r.action,
            actor=r.actor,
            note=r.note,
            created_at=r.created_at,
        )
        for r in rows
    ]
