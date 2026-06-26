"""Persistence access for the ingest pipeline (O-003, ADR-0003).

Functions take an AsyncSession the CALLER owns — the pipeline owns session lifecycle so
the get_tenant_session autobegin discipline (no nested session.begin(), ADR-0026) lives
in one place. Chain ops run on a privileged session (rule 7); tenant writes run on a
get_tenant_session (app role). The chain append is serialised by a transaction-scoped
advisory lock so concurrent appends produce one contiguous chain.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrator.persistence import hash_chain
from orchestrator.persistence.models.dead_letter import DeadLetterEntry
from orchestrator.persistence.models.forward_outbox import ForwardOutbox
from orchestrator.persistence.models.ingest_audit_log import IngestAuditLog
from orchestrator.persistence.models.ingest_event import IngestEvent

# Deterministic transaction-scoped advisory-lock key for chain-append serialisation
# (a stable bigint derived from a domain label; computed at import, not random).
_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:ingest-audit-chain").digest()[:8],
    "big",
    signed=True,
)

# The F-002 common fields the audit chain folds in (also the columns the chain row needs).
_COMMON_FIELDS = (
    "event_id",
    "event_type",
    "event_timestamp",
    "request_id",
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
)


# --------------------------------------------------------------------------- #
# Tenant-scoped reads/writes (app role, get_tenant_session)
# --------------------------------------------------------------------------- #


async def tenant_event_content_hash(session: AsyncSession, idempotency_key: str) -> str | None:
    """Return the content_hash of an existing ingest_events row for *idempotency_key*.

    Runs under the tenant session, so it sees only the current tenant's row (the common
    re-delivery case). None when absent (or RLS-hidden cross-tenant).
    """
    result = await session.execute(
        text("SELECT content_hash FROM ingest_events WHERE idempotency_key = :k"),
        {"k": idempotency_key},
    )
    return result.scalar_one_or_none()


async def insert_ingest_event(session: AsyncSession, row: dict[str, Any]) -> None:
    """INSERT one ingest_events row (tenant session). Caller commits."""
    await session.execute(insert(IngestEvent).values(**row))


async def insert_forward_outbox(
    session: AsyncSession,
    *,
    outbox_id: str,
    tenant_id: str,
    event_id: str,
    idempotency_key: str,
) -> None:
    """INSERT one forward_outbox row recording forward-INTENT (tenant session)."""
    await session.execute(
        insert(ForwardOutbox).values(
            id=outbox_id,
            tenant_id=tenant_id,
            event_id=event_id,
            idempotency_key=idempotency_key,
            status="pending",
        )
    )


# --------------------------------------------------------------------------- #
# Privileged reads/writes (chain + DLQ)
# --------------------------------------------------------------------------- #


async def privileged_event_content_hash(session: AsyncSession, idempotency_key: str) -> str | None:
    """Cross-tenant content_hash lookup on the privileged (BYPASSRLS) session.

    Used ONLY on the rare unique-violation path to resolve benign-duplicate vs
    idempotency_conflict globally (the app role cannot read another tenant's row).
    """
    result = await session.execute(
        text("SELECT content_hash FROM ingest_events WHERE idempotency_key = :k"),
        {"k": idempotency_key},
    )
    return result.scalar_one_or_none()


async def insert_dead_letter(session: AsyncSession, row: dict[str, Any]) -> None:
    """INSERT one dead_letter_queue failure-envelope row (privileged session).

    Privileged because tenant_id may be NULL (payload-invalid) which the app role's RLS
    WITH CHECK would reject; RLS still scopes DLQ READS.
    """
    await session.execute(insert(DeadLetterEntry).values(**row))


async def chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent row_hash, or GENESIS_HASH if the chain is empty."""
    result = await session.execute(
        text("SELECT row_hash FROM ingest_audit_log ORDER BY sequence_number DESC LIMIT 1")
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.GENESIS_HASH


async def append_audit_link(
    session: AsyncSession,
    fields: dict[str, Any],
    *,
    disposition: str,
    dlq_reason: str | None = None,
    dlq_id: str | None = None,
) -> str:
    """Append one hash-chained ingest_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock serialises concurrent appends so prev_hash always
    references the true tip. Returns the new row_hash. dlq_reason/dlq_id follow the
    opt-in-when-present hash rule.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CHAIN_LOCK_KEY})
    prev_hash = await chain_tip_hash(session)
    row = {
        key: fields[key]
        for key in (*_COMMON_FIELDS, "envelope_id", "idempotency_key", "source_product")
    }
    row["disposition"] = disposition
    row["dlq_reason"] = dlq_reason
    row["dlq_id"] = dlq_id
    row["prev_hash"] = prev_hash
    row["row_hash"] = hash_chain.compute_row_hash(row)
    await session.execute(insert(IngestAuditLog).values(**row))
    return row["row_hash"]


async def validate_chain(session: AsyncSession) -> bool:
    """Re-validate the full chain in order: each row_hash recomputes and links to prev.

    Returns True iff every link verifies. O(n) — privileged session (sees all tenants).

    FAIL-LOUD (audit L-2): the chain is global and is read with NO tenant GUC, so under a
    non-BYPASSRLS role the RLS predicate hides every row and the loop would vacuously
    return True ("integrity verified" over an invisible chain). Assert the role bypasses
    RLS first; otherwise raise rather than report a false pass.
    """
    bypass = (
        await session.execute(
            text(
                "SELECT bool_or(rolbypassrls OR rolsuper) FROM pg_roles "
                "WHERE rolname = current_user"
            )
        )
    ).scalar()
    if not bypass:
        raise RuntimeError(
            "validate_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees an RLS-scoped subset and would falsely report integrity."
        )
    result = await session.execute(
        select(IngestAuditLog).order_by(IngestAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "event_id": row.event_id,
            "event_type": row.event_type,
            "event_timestamp": row.event_timestamp,
            "request_id": row.request_id,
            "tenant_id": row.tenant_id,
            "team_id": row.team_id,
            "project_id": row.project_id,
            "agent_id": row.agent_id,
            "envelope_id": row.envelope_id,
            "idempotency_key": row.idempotency_key,
            "source_product": row.source_product,
            "disposition": row.disposition,
            "dlq_reason": row.dlq_reason,
            "dlq_id": row.dlq_id,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True
