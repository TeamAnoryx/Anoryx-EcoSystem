"""Bank-aggregation HTTP surface: ``/v1/admin/bank-aggregation/*`` (D-025).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)``.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route — like every other B2C-track router, this is an internal
operator/testing surface until the real B2C onboarding shell (still unbuilt anywhere
in this ecosystem) exists to front it with genuine end-user auth.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import LinkedInstitutionId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    LinkCreateRequest,
    LinkRevokeRequest,
    LinkView,
    SyncRunCreateRequest,
    SyncRunView,
)
from .service import (
    AccountAlreadyLinkedError,
    AccountNotFoundError,
    LinkAlreadyRevokedError,
    LinkNotFoundError,
    LinkRevokedError,
)

router = APIRouter(prefix="/v1/admin/bank-aggregation", dependencies=[Depends(require_admin)])


@router.post("/links", status_code=201, response_model=LinkView)
async def post_link(req: LinkCreateRequest) -> LinkView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_link(session, req)
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="account_not_found") from exc
        except AccountAlreadyLinkedError as exc:
            raise HTTPException(status_code=409, detail="account_already_linked") from exc


@router.get("/links", response_model=list[LinkView])
async def get_links(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[LinkView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_link_views(session, limit=limit)


@router.post("/links/{link_id}/revoke", response_model=LinkView)
async def post_revoke(link_id: LinkedInstitutionId, req: LinkRevokeRequest) -> LinkView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.revoke_link(session, link_id=link_id, req=req)
        except LinkNotFoundError as exc:
            raise HTTPException(status_code=404, detail="link_not_found") from exc
        except LinkAlreadyRevokedError as exc:
            raise HTTPException(status_code=409, detail="link_already_revoked") from exc


@router.post("/links/{link_id}/sync", status_code=201, response_model=SyncRunView)
async def post_sync(link_id: LinkedInstitutionId, req: SyncRunCreateRequest) -> SyncRunView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.sync_link(session, link_id=link_id, req=req)
        except LinkNotFoundError as exc:
            raise HTTPException(status_code=404, detail="link_not_found") from exc
        except LinkRevokedError as exc:
            raise HTTPException(status_code=409, detail="link_revoked") from exc
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="account_not_found") from exc


@router.get("/links/{link_id}/sync-runs", response_model=list[SyncRunView])
async def get_sync_runs(
    link_id: LinkedInstitutionId, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[SyncRunView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_sync_run_views(session, link_id=link_id, limit=limit)
