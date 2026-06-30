"""Dead-letter sink (ADR-0004 Fork 5; vectors 4, 8).

An unmappable event is written to ``delta.ingest_dead_letter`` and logged (the alert),
never dropped. A row with a known, well-formed tenant is written via the tenant
session (tenant-visible under RLS); an unknown-tenant row is written via the
privileged session with ``tenant_id`` NULL (RLS-invisible to delta_app), mirroring the
Orchestrator's dead_letter pattern. INSERT is ``ON CONFLICT DO NOTHING`` on the
partial unique ``(tenant_id, source_event_id)`` so a redelivered poison event yields
at most one dead-letter row per (tenant, event) (bounds vector 8).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..persistence.database import get_privileged_session, get_tenant_session
from ..persistence.models import ingest_dead_letter
from .errors import PermanentIngestError

logger = logging.getLogger("delta.ingest.dlq")

_DEDUP_WHERE = text("tenant_id IS NOT NULL AND source_event_id IS NOT NULL")


async def dead_letter(
    error: PermanentIngestError,
    *,
    original_payload: dict,
    attempt_count: int,
) -> None:
    """Persist a dead-letter row for an unmappable event and emit the alert.

    May raise a transient DB error (the caller classifies that as 503 so the event is
    retried rather than lost). A successful write is idempotent on (tenant, event).
    """
    now = datetime.now(timezone.utc)
    values = {
        "dlq_id": str(uuid.uuid4()),
        "tenant_id": error.tenant_id,
        "source_event_id": error.event_id,
        "event_type": error.event_type,
        "reason": error.reason.value,
        "original_payload": original_payload,
        "attempt_count": attempt_count,
        "first_failed_at": now,
        "last_failed_at": now,
    }
    stmt = (
        pg_insert(ingest_dead_letter)
        .values(**values)
        .on_conflict_do_nothing(
            index_elements=["tenant_id", "source_event_id"],
            index_where=_DEDUP_WHERE,
        )
    )

    if error.tenant_id:
        # Well-formed tenant -> tenant-scoped insert (RLS WITH CHECK needs GUC==tenant).
        async with get_tenant_session(error.tenant_id) as session:
            await session.execute(stmt)
            await session.commit()
    else:
        # Unknown tenant -> privileged insert, tenant_id NULL (RLS-invisible to delta_app).
        # NOTE: the partial-unique dedup index excludes NULL tenant_id (its predicate is
        # `tenant_id IS NOT NULL AND source_event_id IS NOT NULL`), so unknown-tenant rows
        # are NOT deduped — a redelivered unknown-tenant poison event can write up to
        # `attempt_count`/max_attempts rows. That is bounded (the dispatcher caps retries)
        # and acceptable: these rows are privileged-only and a tenant-NULL key cannot
        # meaningfully dedupe distinct poison events anyway.
        async with get_privileged_session() as session:
            await session.execute(stmt)
            await session.commit()

    # The alert. No secret/payload body is logged — only the auditable attribution.
    logger.warning(
        "delta.ingest dead-letter: reason=%s tenant=%s event_id=%s event_type=%s attempt=%d",
        error.reason.value,
        error.tenant_id or "<unknown>",
        error.event_id or "<none>",
        error.event_type or "<none>",
        attempt_count,
    )
