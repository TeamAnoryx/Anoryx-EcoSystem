"""Unified CRM HTTP surface: ``/v1/admin/crm/*`` (D-013).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the ``tenant_id`` the caller supplies (query param on GET, body field on POST), the
same "per-target session" shape D-007/D-008/D-011/D-012 all use. ``require_admin``
(imported from ``allocation_admin.auth``, not redefined here — every admin-surface
package in Delta shares the one break-glass auth dependency) gates every route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import DealId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    ClientCreateRequest,
    ClientDetailView,
    ClientView,
    DealCreateRequest,
    DealStageTransitionRequest,
    DealView,
    InteractionCreateRequest,
    InteractionView,
    RelationshipScoreView,
    StakeholderCreateRequest,
    StakeholderView,
)
from .service import (
    ClientNotFoundError,
    CrmScopeMismatchError,
    DealAlreadyTerminalError,
    DealNotFoundError,
    StakeholderNotFoundError,
)

router = APIRouter(prefix="/v1/admin/crm", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


# ------------------------------------------------------------------------- clients


@router.post("/clients", status_code=201, response_model=ClientView)
async def post_client(req: ClientCreateRequest) -> ClientView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_client(session, req)


@router.get("/clients", response_model=list[ClientView])
async def get_clients(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[ClientView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_client_views(session, limit=limit)


@router.get("/clients/{client_id}", response_model=ClientDetailView)
async def get_client_detail(client_id: str, tenant_id: TenantId) -> ClientDetailView:
    async with get_tenant_session(tenant_id) as session:
        try:
            return await service.get_client_detail(session, client_id=client_id)
        except ClientNotFoundError as exc:
            raise _not_found("client_not_found") from exc


# --------------------------------------------------------------------------- deals


@router.post("/clients/{client_id}/deals", status_code=201, response_model=DealView)
async def post_deal(client_id: str, req: DealCreateRequest) -> DealView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_deal(session, client_id=client_id, req=req)
        except ClientNotFoundError as exc:
            raise _not_found("client_not_found") from exc


@router.get("/clients/{client_id}/deals", response_model=list[DealView])
async def get_deals(
    client_id: str, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[DealView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_deal_views(session, client_id=client_id, limit=limit)


@router.post("/deals/{deal_id}/stage", response_model=DealView)
async def post_deal_stage(deal_id: DealId, req: DealStageTransitionRequest) -> DealView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.transition_deal_stage(session, deal_id=deal_id, req=req)
        except DealNotFoundError as exc:
            raise _not_found("deal_not_found") from exc
        except DealAlreadyTerminalError as exc:
            raise HTTPException(status_code=409, detail="deal_already_terminal") from exc


# -------------------------------------------------------------------- stakeholders


@router.post("/clients/{client_id}/stakeholders", status_code=201, response_model=StakeholderView)
async def post_stakeholder(client_id: str, req: StakeholderCreateRequest) -> StakeholderView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_stakeholder(session, client_id=client_id, req=req)
        except ClientNotFoundError as exc:
            raise _not_found("client_not_found") from exc
        except DealNotFoundError as exc:
            raise _not_found("deal_not_found") from exc
        except CrmScopeMismatchError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/clients/{client_id}/stakeholders", response_model=list[StakeholderView])
async def get_stakeholders(
    client_id: str, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[StakeholderView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_stakeholder_views(session, client_id=client_id, limit=limit)


# -------------------------------------------------------------------- interactions


@router.post("/clients/{client_id}/interactions", status_code=201, response_model=InteractionView)
async def post_interaction(client_id: str, req: InteractionCreateRequest) -> InteractionView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_interaction(session, client_id=client_id, req=req)
        except ClientNotFoundError as exc:
            raise _not_found("client_not_found") from exc
        except DealNotFoundError as exc:
            raise _not_found("deal_not_found") from exc
        except StakeholderNotFoundError as exc:
            raise _not_found("stakeholder_not_found") from exc
        except CrmScopeMismatchError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/clients/{client_id}/interactions", response_model=list[InteractionView])
async def get_interactions(
    client_id: str, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[InteractionView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_interaction_views(session, client_id=client_id, limit=limit)


# --------------------------------------------------------------- relationship score


@router.get("/clients/{client_id}/relationship-score", response_model=RelationshipScoreView)
async def get_relationship_score(client_id: str, tenant_id: TenantId) -> RelationshipScoreView:
    async with get_tenant_session(tenant_id) as session:
        return await service.get_relationship_score(session, client_id=client_id)
