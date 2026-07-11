"""Bank-import HTTP surface: ``/v1/admin/bank-imports/*`` (D-025).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)``.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route — like D-021/D-024's routers, an internal operator/testing surface until
a real B2C onboarding shell exists to front it with genuine end-user auth.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import BankSourceId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    ImportRequest,
    ImportResultView,
    ImportSummaryView,
    SourceRegisterRequest,
    SourceView,
)
from .service import AccountNotFoundError, SourceNotFoundError

router = APIRouter(prefix="/v1/admin/bank-imports", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


@router.post("/sources", status_code=201, response_model=SourceView)
async def post_source(req: SourceRegisterRequest) -> SourceView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.register_source(session, req)
        except AccountNotFoundError as exc:
            raise _not_found("account_not_found") from exc


@router.get("/sources", response_model=list[SourceView])
async def get_sources(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[SourceView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_source_views(session, limit=limit)


@router.post("/sources/{source_id}/import", status_code=201, response_model=ImportResultView)
async def post_import(source_id: BankSourceId, req: ImportRequest) -> ImportResultView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.run_import(session, source_id=source_id, req=req)
        except SourceNotFoundError as exc:
            raise _not_found("source_not_found") from exc
        except AccountNotFoundError as exc:
            raise _not_found("account_not_found") from exc


@router.get("/imports", response_model=list[ImportSummaryView])
async def get_imports(
    tenant_id: TenantId,
    source_id: BankSourceId | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[ImportSummaryView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_import_summaries(session, source_id=source_id, limit=limit)
