"""RBAC access-token HTTP surface: ``/v1/admin/rbac/*`` (D-017).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/.../D-016 all use. Token issuance/listing/
revocation are themselves gated at `tenant_admin` (managing WHO has access requires
the highest role) — checked directly via ``rbac.auth.authorize`` (not the router-
level `Depends`, since `tenant_id` here comes from the request body, not a query
param; see auth.py's own docstring).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..identifiers import AccessTokenId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .auth import authorize
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    AccessTokenCreateRequest,
    AccessTokenIssuedView,
    AccessTokenRevokeRequest,
    AccessTokenView,
)
from .service import TokenNotFoundError

router = APIRouter(prefix="/v1/admin/rbac")


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


@router.post("/tokens", status_code=201, response_model=AccessTokenIssuedView)
async def post_token(request: Request, req: AccessTokenCreateRequest) -> AccessTokenIssuedView:
    await authorize(request, req.tenant_id, "tenant_admin")
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_token(session, req)


@router.get("/tokens", response_model=list[AccessTokenView])
async def get_tokens(
    request: Request, tenant_id: TenantId, limit: int = _DEFAULT_LIMIT
) -> list[AccessTokenView]:
    await authorize(request, tenant_id, "tenant_admin")
    async with get_tenant_session(tenant_id) as session:
        return await service.list_token_views(session, limit=limit)


@router.post("/tokens/{token_id}/revoke", response_model=AccessTokenView)
async def post_token_revoke(
    request: Request, token_id: AccessTokenId, req: AccessTokenRevokeRequest
) -> AccessTokenView:
    await authorize(request, req.tenant_id, "tenant_admin")
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.revoke_token(session, token_id=token_id, req=req)
        except TokenNotFoundError as exc:
            raise _not_found("token_not_found") from exc
