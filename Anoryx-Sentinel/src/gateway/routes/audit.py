"""Tenant self-service audit-log read route (F-012a, ADR-0014 §6).

GET /v1/audit — a tenant principal (Bearer virtual key) reads its OWN audit
events. The tenant is server-resolved from the verified key via
resolve_tenant_context (never a client-supplied parameter), and the serving read
runs in get_tenant_session(own tenant) so RLS returns zero rows for any other
tenant (vector 10). Pure read — zero writes, and NO admin access event (this is a
self read, not a cross-tenant operator read).
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from admin.audit_read import read_audit_page, verify_chain
from admin.schemas import AuditEventResponse, AuditPageResponse
from gateway.middleware.tenant_context import resolve_tenant_context
from persistence.database import get_tenant_session

tenant_audit_router = APIRouter(tags=["audit"])


@tenant_audit_router.get("/v1/audit", response_model=AuditPageResponse)
async def read_own_audit(
    request: Request,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> AuditPageResponse:
    """Read the calling tenant's own audit events (RLS-scoped, read-only)."""
    ctx = resolve_tenant_context(request)  # server-resolved tenant; 403 on mismatch

    async with get_tenant_session(ctx.tenant_id) as ts:
        rows, bounded = await read_audit_page(
            ts, tenant_id=ctx.tenant_id, after_sequence=after_sequence, limit=limit
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
