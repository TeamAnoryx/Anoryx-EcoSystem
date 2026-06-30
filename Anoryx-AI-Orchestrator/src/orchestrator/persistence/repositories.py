"""Persistence access for the ingest pipeline (O-003, ADR-0003).

Functions take an AsyncSession the CALLER owns — the pipeline owns session lifecycle so
the get_tenant_session autobegin discipline (no nested session.begin(), ADR-0026) lives
in one place. Chain ops run on a privileged session (rule 7); tenant writes run on a
get_tenant_session (app role). The chain append is serialised by a transaction-scoped
advisory lock so concurrent appends produce one contiguous chain.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
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


# =========================================================================== #
# Policy distribution persistence (O-004, ADR-0004) — ADDITIVE, parallel to the
# ingest functions above. Own advisory-lock key, own tip query, own chain. The
# new model classes + `update` are imported inside each function so this whole
# block is purely appended (the shipped O-003 body above is byte-identical, so
# the ingest chain still hashes identically). Tenant-scoped fns run on a
# caller-owned RLS-scoped session (caller commits); chain fns run on a privileged
# session under `async with session.begin()`.
# =========================================================================== #

# Distinct transaction-scoped advisory-lock key for the distribution-chain append
# (a stable bigint from a domain label, distinct from _CHAIN_LOCK_KEY).
_DISTRIBUTION_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:distribution-audit-chain").digest()[:8],
    "big",
    signed=True,
)

# Attribution fields the distribution chain folds in (also the chain row's columns).
_DISTRIBUTION_COMMON_FIELDS = ("distribution_id", "policy_id", "tenant_id", "policy_type")


# --------------------------------------------------------------------------- #
# Tenant-scoped reads/writes (app role, get_tenant_session)
# --------------------------------------------------------------------------- #


async def insert_policy_distribution(session: AsyncSession, row: dict[str, Any]) -> None:
    """INSERT one policy_distributions row (tenant session). Caller commits."""
    from orchestrator.persistence.models.policy_distribution import PolicyDistribution

    await session.execute(insert(PolicyDistribution).values(**row))


async def insert_distribution_target(session: AsyncSession, row: dict[str, Any]) -> None:
    """INSERT one policy_distribution_targets row (tenant session). Caller commits."""
    from orchestrator.persistence.models.policy_distribution_target import (
        PolicyDistributionTarget,
    )

    await session.execute(insert(PolicyDistributionTarget).values(**row))


async def update_target_state(
    session: AsyncSession,
    *,
    target_id: str,
    state: str,
    attempt_count: int | None = None,
    last_error: str | None = None,
    distributed_at: object | None = None,
    next_attempt_at: object | None = None,
) -> None:
    """UPDATE one target's state + retry bookkeeping (tenant session). Caller commits.

    Only the provided fields are written; a None argument is omitted from the SET clause so
    a caller can advance `state` without clobbering attempt_count/last_error/timestamps.
    `updated_at` is stamped (tz-aware UTC now) on EVERY transition so the row records when its
    last attempt/state-change happened — the GET status read surfaces it as last_attempt_at for
    a failed (or pending-after-attempt) target that has no distributed_at.
    """
    from sqlalchemy import update

    from orchestrator.persistence.models.policy_distribution_target import (
        PolicyDistributionTarget,
    )

    values: dict[str, Any] = {"state": state, "updated_at": datetime.now(timezone.utc)}
    if attempt_count is not None:
        values["attempt_count"] = attempt_count
    if last_error is not None:
        values["last_error"] = last_error
    if distributed_at is not None:
        values["distributed_at"] = distributed_at
    if next_attempt_at is not None:
        values["next_attempt_at"] = next_attempt_at
    await session.execute(
        update(PolicyDistributionTarget)
        .where(PolicyDistributionTarget.target_id == target_id)
        .values(**values)
    )


async def update_distribution_state(
    session: AsyncSession, *, distribution_id: str, state: str
) -> None:
    """UPDATE the parent policy_distributions.state aggregate (tenant session). Caller commits."""
    from sqlalchemy import update

    from orchestrator.persistence.models.policy_distribution import PolicyDistribution

    await session.execute(
        update(PolicyDistribution)
        .where(PolicyDistribution.distribution_id == distribution_id)
        .values(state=state)
    )


async def get_distribution(session: AsyncSession, distribution_id: str) -> dict[str, Any] | None:
    """Return the policy_distributions row as a dict, or None (tenant session, RLS-scoped)."""
    from orchestrator.persistence.models.policy_distribution import PolicyDistribution

    result = await session.execute(
        select(PolicyDistribution).where(PolicyDistribution.distribution_id == distribution_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in PolicyDistribution.__table__.columns}


async def list_distribution_targets(
    session: AsyncSession, distribution_id: str
) -> list[dict[str, Any]]:
    """Return every target row for *distribution_id* as dicts (tenant session, RLS-scoped)."""
    from orchestrator.persistence.models.policy_distribution_target import (
        PolicyDistributionTarget,
    )

    result = await session.execute(
        select(PolicyDistributionTarget)
        .where(PolicyDistributionTarget.distribution_id == distribution_id)
        .order_by(PolicyDistributionTarget.target_id.asc())
    )
    return [
        {c.name: getattr(row, c.name) for c in PolicyDistributionTarget.__table__.columns}
        for row in result.scalars()
    ]


# --------------------------------------------------------------------------- #
# Privileged reads/writes (distribution chain)
# --------------------------------------------------------------------------- #


async def distribution_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent distribution_audit_log row_hash, or DISTRIBUTION_GENESIS_HASH."""
    result = await session.execute(
        text("SELECT row_hash FROM distribution_audit_log ORDER BY sequence_number DESC LIMIT 1")
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.DISTRIBUTION_GENESIS_HASH


async def append_distribution_audit_link(
    session: AsyncSession,
    fields: dict[str, Any],
    *,
    disposition: str,
    sentinel_id: str | None = None,
    error_reason: str | None = None,
) -> str:
    """Append one hash-chained distribution_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. sentinel_id/error_reason
    follow the opt-in-when-present hash rule.
    """
    from orchestrator.persistence.models.distribution_audit_log import DistributionAuditLog

    await session.execute(
        text("SELECT pg_advisory_xact_lock(:k)"), {"k": _DISTRIBUTION_CHAIN_LOCK_KEY}
    )
    prev_hash = await distribution_chain_tip_hash(session)
    row = {key: fields[key] for key in _DISTRIBUTION_COMMON_FIELDS}
    row["disposition"] = disposition
    row["sentinel_id"] = sentinel_id
    row["error_reason"] = error_reason
    row["prev_hash"] = prev_hash
    row["row_hash"] = hash_chain.compute_distribution_row_hash(row)
    await session.execute(insert(DistributionAuditLog).values(**row))
    return row["row_hash"]


async def validate_distribution_chain(session: AsyncSession) -> bool:
    """Re-validate the full distribution chain in order: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (sees all tenants).

    FAIL-LOUD (mirrors validate_chain, audit L-2): the chain is global and is read with NO
    tenant GUC, so under a non-BYPASSRLS role the RLS predicate hides every row and the loop
    would vacuously return True over an invisible chain. Assert the role bypasses RLS first;
    otherwise raise rather than report a false pass.
    """
    from orchestrator.persistence.models.distribution_audit_log import DistributionAuditLog

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
            "validate_distribution_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees an RLS-scoped subset and would falsely report integrity."
        )
    result = await session.execute(
        select(DistributionAuditLog).order_by(DistributionAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.DISTRIBUTION_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "distribution_id": row.distribution_id,
            "policy_id": row.policy_id,
            "tenant_id": row.tenant_id,
            "policy_type": row.policy_type,
            "disposition": row.disposition,
            "sentinel_id": row.sentinel_id,
            "error_reason": row.error_reason,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_distribution_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True
