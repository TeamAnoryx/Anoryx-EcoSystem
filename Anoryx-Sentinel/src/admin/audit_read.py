"""Shared audit-log read helpers (F-012a, ADR-0014 §6 D5/D8).

Both the admin operator audit read (/admin/tenants/{id}/audit) and the tenant
self read (/audit) use these:

  read_audit_page() — a PURE keyset SELECT on the caller-scoped session (RLS).
    Zero writes (R5/vector 9).
  verify_chain()    — runs validate_chain() on a SEPARATE privileged session and
    returns its honest result (vector 11). The global F-003 chain requires the
    privileged role; it returns only validity metadata, never tenant data.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from persistence.database import get_privileged_session
from persistence.models.events_audit_log import EventsAuditLog
from persistence.repositories.audit_log_repository import AuditLogRepository, ChainValidationResult

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


async def read_audit_page(
    session: AsyncSession,
    *,
    tenant_id: str,
    after_sequence: int = 0,
    limit: int = _DEFAULT_LIMIT,
) -> tuple[list[EventsAuditLog], int]:
    """Return (rows, effective_limit) for a keyset page of the tenant's events.

    Pure read on the caller-scoped session (RLS enforced). Returns the effective
    limit so the caller can compute next_cursor (full page => more may exist).
    """
    bounded = max(1, min(limit, _MAX_LIMIT))
    rows = await AuditLogRepository(session).list_for_tenant_after(
        tenant_id, after_sequence=after_sequence, limit=bounded
    )
    return rows, bounded


async def verify_chain() -> ChainValidationResult:
    """Validate the global F-003 hash chain on a fresh privileged session.

    O(chain length) — acceptable at design-partner scale; a windowed verification
    is a documented future optimization (ADR-0014). Returns validity metadata
    only (is_valid, rows_checked), never any tenant row.
    """
    async with get_privileged_session() as ps:
        async with ps.begin():
            return await AuditLogRepository(ps).validate_chain()
