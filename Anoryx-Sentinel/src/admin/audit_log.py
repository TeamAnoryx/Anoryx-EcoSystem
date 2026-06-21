"""Admin audit-log read route (F-012a, ADR-0014 §6 D5/D8).

GET /admin/tenants/{tenant_id}/audit — operator reads a TARGET tenant's audit
events. Keyset cursor on sequence_number. The serving SELECT runs in
get_tenant_session(TARGET) (RLS-scoped) and writes ZERO rows (R5/vector 9). The
R1 cross-tenant access requirement is satisfied by a SEPARATE privileged append
of admin_audit_accessed (D8) — distinct from the serving query. The F-003 chain
verification status is surfaced honestly (vector 11).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from admin.audit import emit_admin_event
from admin.audit_read import read_audit_page, verify_chain
from admin.schemas import AuditEventResponse, AuditPageResponse
from admin.scope import enforce_admin_scope
from admin.util import actor_id, request_id, validate_tenant_id_path
from persistence.database import get_privileged_session, get_tenant_session

# Router deps: validate the path tenant_id, then enforce the operator's tenant-pin
# + role (ADR-0017 §3 D2, R1). require_admin runs at the parent admin_router.
audit_log_router = APIRouter(
    tags=["admin"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)


@audit_log_router.get("/tenants/{tenant_id}/audit", response_model=AuditPageResponse)
async def read_tenant_audit(
    tenant_id: str,
    request: Request,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> AuditPageResponse:
    """Operator read of a target tenant's audit events (audited, read-only)."""
    rid = request_id(request)
    aid = actor_id(request)

    # R1/D8: the cross-tenant access is audited via a SEPARATE privileged append,
    # BEFORE the read — never from the serving query (which stays zero-write).
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_audit_accessed",
                target_tenant_id=tenant_id,
                request_id=rid,
                actor_id=aid,
            )

    # Serving read: RLS-scoped to the TARGET tenant; pure SELECT (R5/vector 9).
    async with get_tenant_session(tenant_id) as ts:
        rows, bounded = await read_audit_page(
            ts, tenant_id=tenant_id, after_sequence=after_sequence, limit=limit
        )
        events = [AuditEventResponse.model_validate(r) for r in rows]

    chain = await verify_chain()
    next_cursor = rows[-1].sequence_number if rows and len(rows) == bounded else None
    return AuditPageResponse(
        events=events,
        count=len(events),
        next_cursor=next_cursor,
        chain_verified=chain.is_valid,
        chain_rows_checked=chain.rows_checked,
    )
