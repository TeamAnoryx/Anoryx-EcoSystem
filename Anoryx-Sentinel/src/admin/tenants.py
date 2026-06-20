"""Admin tenant lifecycle routes (F-012a, ADR-0014 §4).

Create / list / get / soft-deactivate tenants. The `tenants` registry is global
(non-RLS), so every op runs on the privileged session (TenantRepository). NO hard
delete (R3) — deactivate flips is_active. Create + deactivate emit an admin event
(admin-console + target tenant) in the SAME privileged transaction (atomic).

Registry reads (list/get) are operator metadata over the non-tenant-scoped
registry, not reads of a tenant's protected data, so they do not emit an access
event; the cross-tenant DATA reads (audit/keys/policies/config) do (STEP 5/6).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from admin.audit import emit_admin_event
from admin.schemas import TenantCreateRequest, TenantListResponse, TenantResponse
from admin.util import parse_body, request_id, validate_tenant_id_path
from persistence.database import get_privileged_session
from persistence.repositories.tenant_repository import TenantNotFoundError, TenantRepository
from persistence.repositories.virtual_api_key_repository import VirtualApiKeyRepository

tenants_router = APIRouter(tags=["admin"])


@tenants_router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tenant(request: Request) -> TenantResponse:
    """Create a tenant. Emits admin_tenant_created in the same transaction."""
    body = await parse_body(request, TenantCreateRequest)
    rid = request_id(request)
    async with get_privileged_session() as session:
        async with session.begin():
            repo = TenantRepository(session)
            row = await repo.create(name=body.name, display_name=body.display_name)
            await emit_admin_event(
                session,
                event_type="admin_tenant_created",
                target_tenant_id=row.tenant_id,
                request_id=rid,
            )
            return TenantResponse.model_validate(row)


@tenants_router.get("/tenants", response_model=TenantListResponse)
async def list_tenants(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> TenantListResponse:
    """List all tenants (active and inactive), newest-first."""
    async with get_privileged_session() as session:
        async with session.begin():
            rows = await TenantRepository(session).list_all(limit=limit, offset=offset)
            tenants = [TenantResponse.model_validate(r) for r in rows]
    return TenantListResponse(tenants=tenants, count=len(tenants))


@tenants_router.get(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    dependencies=[Depends(validate_tenant_id_path)],
)
async def get_tenant(tenant_id: str) -> TenantResponse:
    """Get one tenant by id. 404 if not found."""
    async with get_privileged_session() as session:
        async with session.begin():
            try:
                row = await TenantRepository(session).get_by_id(tenant_id)
            except TenantNotFoundError:
                raise HTTPException(status_code=404, detail="tenant_not_found") from None
            return TenantResponse.model_validate(row)


@tenants_router.post(
    "/tenants/{tenant_id}/deactivate",
    response_model=TenantResponse,
    dependencies=[Depends(validate_tenant_id_path)],
)
async def deactivate_tenant(tenant_id: str, request: Request) -> TenantResponse:
    """Soft-deactivate a tenant (is_active=False). No hard delete (R3).

    Emits admin_tenant_deactivated. The audit log + hash chain are untouched.
    """
    rid = request_id(request)
    async with get_privileged_session() as session:
        async with session.begin():
            repo = TenantRepository(session)
            try:
                row = await repo.deactivate(tenant_id)
            except TenantNotFoundError:
                raise HTTPException(status_code=404, detail="tenant_not_found") from None
            # Cascade (vector 13): deactivate the tenant's keys so the gateway denies
            # them. Runs on the same privileged session (BYPASSRLS) in one transaction
            # with the tenant flip + the audit event.
            await VirtualApiKeyRepository(session).deactivate_all_for_tenant(tenant_id)
            await emit_admin_event(
                session,
                event_type="admin_tenant_deactivated",
                target_tenant_id=tenant_id,
                request_id=rid,
            )
            return TenantResponse.model_validate(row)
