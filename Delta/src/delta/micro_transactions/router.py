"""Micro-transaction execution HTTP surface: ``/v1/admin/micro-transactions/*``
(D-024).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)``.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route — like D-021's own router, this is an internal operator/testing surface
until the real B2C onboarding shell (still unbuilt anywhere in this ecosystem) exists
to front it with genuine end-user auth.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import PersonalAccountId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import ExecutionRequest, ExecutionStatus, ExecutionView
from .service import AccountNotFoundError

router = APIRouter(prefix="/v1/admin/micro-transactions", dependencies=[Depends(require_admin)])


@router.post("/execute", status_code=201, response_model=ExecutionView)
async def post_execute(req: ExecutionRequest) -> ExecutionView:
    """Synchronous accept/reject execution. 201 either way — a REJECTED attempt is
    still a created execution record (the trace is a security feature); the body's
    ``status``/``rejection_reason`` carry the decision, and ``idempotent_replay``
    marks a replayed key returning its stored original outcome."""
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.execute_micro_transaction(session, req)
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="account_not_found") from exc


@router.get("", response_model=list[ExecutionView])
async def get_executions(
    tenant_id: TenantId,
    account_id: PersonalAccountId | None = None,
    status: ExecutionStatus | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[ExecutionView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_execution_views(
            session, account_id=account_id, status=status, limit=limit
        )
