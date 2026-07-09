"""RBAC authorization dependency (D-017, ADR-0017).

``require_role(minimum)`` is an ADDITIVE widening of who can authenticate against a
gated route — the original break-glass ``DELTA_ADMIN_TOKEN`` (D-007's
``allocation_admin.auth.require_admin``) continues to work completely unchanged,
treated as implicit `tenant_admin` for any tenant (exactly like ``require_admin``'s
own cross-tenant break-glass behavior). A caller presenting an issued access token
instead is looked up by its hash within the tenant-scoped RLS session for the
``tenant_id`` the route itself already requires — a token issued for a DIFFERENT
tenant is simply invisible there (fails closed as "not found"), not a separate
mismatch check.
"""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request

from ..allocation_admin.config import AllocationAdminSettings
from ..identifiers import TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import AccessRole

_UNAUTHORIZED = 401


def _extract_bearer(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    presented = auth_header[len("Bearer ") :]
    return presented or None


async def authorize(request: Request, tenant_id: str, minimum: AccessRole) -> AccessRole:
    """The core check, callable directly from a route handler once `tenant_id` is
    already known (e.g. parsed from a POST body) — used where a query-param-shaped
    FastAPI dependency (see `require_role` below) doesn't fit."""
    presented = _extract_bearer(request)
    if presented is None:
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    settings: AllocationAdminSettings = request.app.state.allocation_admin_settings
    if hmac.compare_digest(presented, settings.admin_token):
        # The break-glass bearer is cross-tenant and always at least tenant_admin.
        return "tenant_admin"

    async with get_tenant_session(tenant_id) as session:
        role = await service.resolve_role_from_bearer(session, bearer_token=presented)
    if role is None or not service.role_at_least(role, minimum):
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")
    return role


def require_role(minimum: AccessRole) -> Callable[[Request, TenantId], Awaitable[AccessRole]]:
    """Returns a FastAPI dependency gating a route at role `minimum` or above. The
    dependency declares `tenant_id: TenantId` itself, so it composes with any route
    (or router) whose own path/query already carries a `tenant_id` QUERY parameter of
    the same name/type — FastAPI resolves it once, shared between the dependency and
    the route handler (D-008's dashboards router, all three routes: GET-only)."""

    async def _dependency(request: Request, tenant_id: TenantId) -> AccessRole:
        return await authorize(request, tenant_id, minimum)

    return _dependency
