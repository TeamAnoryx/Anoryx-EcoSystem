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


# =========================================================================== #
# Sentinel-registry persistence (O-005, ADR-0005) — ADDITIVE, parallel to the ingest
# and distribution blocks above. The registry is OPERATOR-GLOBAL infra (no tenant
# dimension, no RLS): every function runs on the PRIVILEGED session the caller owns
# (coordination.registry opens it). The new model classes are imported inside each
# function so this whole block is purely appended (the shipped O-003/O-004 body above is
# byte-identical, so the ingest + distribution chains still hash identically). The
# registry-mutation chain has its OWN advisory-lock key + genesis + field set.
# =========================================================================== #

# Distinct transaction-scoped advisory-lock key for the registry-chain append (a stable
# bigint from a domain label, distinct from the ingest + distribution keys).
_REGISTRY_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:registry-audit-chain").digest()[:8],
    "big",
    signed=True,
)


# --------------------------------------------------------------------------- #
# Registry data access (privileged session — operator-global, no RLS)
# --------------------------------------------------------------------------- #


async def insert_sentinel(session: AsyncSession, row: dict[str, Any]) -> None:
    """INSERT one sentinel_registry row (privileged session). Caller commits."""
    from orchestrator.persistence.models.sentinel_registry import SentinelRegistry

    await session.execute(insert(SentinelRegistry).values(**row))


async def update_sentinel(
    session: AsyncSession, *, sentinel_id: str, values: dict[str, Any]
) -> int:
    """UPDATE a sentinel_registry row's mutable fields (privileged session). Returns rowcount.

    `updated_at` is always stamped. Caller commits. A rowcount of 0 means the id is unknown.
    """
    from sqlalchemy import update

    from orchestrator.persistence.models.sentinel_registry import SentinelRegistry

    to_set = {**values, "updated_at": datetime.now(timezone.utc)}
    result = await session.execute(
        update(SentinelRegistry).where(SentinelRegistry.sentinel_id == sentinel_id).values(**to_set)
    )
    return result.rowcount


async def update_sentinel_health(
    session: AsyncSession,
    *,
    sentinel_id: str,
    health_status: str,
    consecutive_failures: int,
    last_checked_at: object,
    last_healthy_at: object | None = None,
) -> None:
    """UPDATE one sentinel's health fields after a probe (privileged session). Caller commits.

    last_healthy_at is only written when provided (a successful probe); on a failed probe it is
    omitted so the row keeps the timestamp of the last success.
    """
    from sqlalchemy import update

    from orchestrator.persistence.models.sentinel_registry import SentinelRegistry

    values: dict[str, Any] = {
        "health_status": health_status,
        "consecutive_failures": consecutive_failures,
        "last_checked_at": last_checked_at,
        "updated_at": datetime.now(timezone.utc),
    }
    if last_healthy_at is not None:
        values["last_healthy_at"] = last_healthy_at
    await session.execute(
        update(SentinelRegistry).where(SentinelRegistry.sentinel_id == sentinel_id).values(**values)
    )


async def delete_sentinel(session: AsyncSession, sentinel_id: str) -> int:
    """DELETE one sentinel_registry row (privileged session). Returns rowcount. Caller commits."""
    from sqlalchemy import delete

    from orchestrator.persistence.models.sentinel_registry import SentinelRegistry

    result = await session.execute(
        delete(SentinelRegistry).where(SentinelRegistry.sentinel_id == sentinel_id)
    )
    return result.rowcount


async def get_sentinel(session: AsyncSession, sentinel_id: str) -> dict[str, Any] | None:
    """Return one sentinel_registry row as a dict, or None (privileged session)."""
    from orchestrator.persistence.models.sentinel_registry import SentinelRegistry

    result = await session.execute(
        select(SentinelRegistry).where(SentinelRegistry.sentinel_id == sentinel_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in SentinelRegistry.__table__.columns}


async def list_sentinels(session: AsyncSession) -> list[dict[str, Any]]:
    """Return every sentinel_registry row as dicts, ordered by sentinel_id (privileged session)."""
    from orchestrator.persistence.models.sentinel_registry import SentinelRegistry

    result = await session.execute(
        select(SentinelRegistry).order_by(SentinelRegistry.sentinel_id.asc())
    )
    return [
        {c.name: getattr(row, c.name) for c in SentinelRegistry.__table__.columns}
        for row in result.scalars()
    ]


# --------------------------------------------------------------------------- #
# Registry-mutation audit chain (privileged session)
# --------------------------------------------------------------------------- #


async def registry_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent sentinel_registry_audit_log row_hash, or REGISTRY_GENESIS_HASH."""
    result = await session.execute(
        text(
            "SELECT row_hash FROM sentinel_registry_audit_log "
            "ORDER BY sequence_number DESC LIMIT 1"
        )
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.REGISTRY_GENESIS_HASH


async def append_registry_audit_link(
    session: AsyncSession,
    *,
    sentinel_id: str,
    action: str,
    disposition: str,
    endpoint: str | None = None,
    capabilities: str | None = None,
    error_reason: str | None = None,
) -> str:
    """Append one hash-chained sentinel_registry_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. endpoint/capabilities/error_reason
    follow the opt-in-when-present hash rule (capabilities is a canonical JSON STRING, hashed
    iff not None). A `rejected` disposition records an SSRF-blocked attempt tamper-evidently.
    """
    from orchestrator.persistence.models.sentinel_registry_audit_log import (
        SentinelRegistryAuditLog,
    )

    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _REGISTRY_CHAIN_LOCK_KEY})
    prev_hash = await registry_chain_tip_hash(session)
    row = {
        "sentinel_id": sentinel_id,
        "action": action,
        "disposition": disposition,
        "endpoint": endpoint,
        "capabilities": capabilities,
        "error_reason": error_reason,
        "prev_hash": prev_hash,
    }
    row["row_hash"] = hash_chain.compute_registry_row_hash(row)
    await session.execute(insert(SentinelRegistryAuditLog).values(**row))
    return row["row_hash"]


async def validate_registry_chain(session: AsyncSession) -> bool:
    """Re-validate the full registry-mutation chain in order: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (the chain is global).

    FAIL-LOUD (mirrors validate_distribution_chain, audit L-2): the registry tables carry no
    RLS, but a non-BYPASSRLS role lacks even SELECT here, so assert the role bypasses RLS first
    (a privileged session) rather than risk a vacuous pass over an empty/denied read.
    """
    from orchestrator.persistence.models.sentinel_registry_audit_log import (
        SentinelRegistryAuditLog,
    )

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
            "validate_registry_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees a denied/empty read and would falsely report integrity."
        )
    result = await session.execute(
        select(SentinelRegistryAuditLog).order_by(SentinelRegistryAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.REGISTRY_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "sentinel_id": row.sentinel_id,
            "action": row.action,
            "disposition": row.disposition,
            "endpoint": row.endpoint,
            "capabilities": row.capabilities,
            "error_reason": row.error_reason,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_registry_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True


# =========================================================================== #
# Per-tenant query principal + tenant-scoped metadata read seams (O-006, ADR-0006) —
# ADDITIVE, parallel to the blocks above. The principal resolver runs on the PRIVILEGED
# session (the operator-global query_service_tokens table has no RLS + no app-role grant, and
# the auth lookup must resolve the tenant BEFORE any tenant GUC is set). The read seams run on
# a caller-owned RLS-scoped get_tenant_session — they carry NO explicit tenant predicate; RLS
# is the structural enforcer (a token physically cannot widen past its tenant). Every read is
# METADATA-ONLY (never `payload`, never `original_envelope`), cursor-paginated, and Limit-
# bounded. The shipped O-003/O-004/O-005 body above is byte-identical, so all three hash chains
# still hash identically.
# =========================================================================== #

# The EventMetadata projection columns (openapi.yaml EventMetadata) — join keys + type + time.
# `payload` is deliberately EXCLUDED (honesty boundary c). sequence_number is selected only to
# compute the opaque cursor; it is NOT part of the projected metadata.
_EVENT_METADATA_COLUMNS = (
    "event_id",
    "event_type",
    "event_timestamp",
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
    "request_id",
)

# The DeadLetterMetadata projection columns (openapi.yaml DeadLetterMetadata). `source_sequence`
# maps to the contract's `sequence`. `original_envelope` is deliberately EXCLUDED (never
# re-expose a full payload on a read seam). created_at is selected only for the cursor.
_DEAD_LETTER_METADATA_COLUMNS = (
    "dlq_id",
    "reason",
    "attempt_count",
    "first_failed_at",
    "event_type",
    "source_product",
    "source_sequence",
)


async def resolve_principal_tenant(session: AsyncSession, token_sha256: str) -> str | None:
    """Resolve a presented token's SHA-256 hash to its tenant_id (PRIVILEGED session).

    Reads query_service_tokens (operator-global, no RLS, no app-role grant) on the privileged
    session — the auth bootstrap must resolve the tenant BEFORE any tenant GUC is set. Returns
    the tenant_id for an ENABLED token, else None. Unknown and disabled are indistinguishable
    (both → None → a uniform 401 at the boundary: no enumeration oracle). Only the hash is
    read here; the plaintext token is never read or logged.
    """
    result = await session.execute(
        text("SELECT tenant_id FROM query_service_tokens " "WHERE token_sha256 = :h AND enabled"),
        {"h": token_sha256},
    )
    return result.scalar_one_or_none()


async def list_events(
    session: AsyncSession,
    *,
    filters: dict[str, Any],
    limit: int,
    cursor: int | None,
) -> tuple[list[dict[str, Any]], int | None]:
    """Cursor-paginated, metadata-only read of ingest_events (tenant session, RLS-scoped).

    Runs on get_tenant_session so RLS scopes rows to the principal's tenant (NO explicit
    tenant predicate — the DB enforces isolation). Projects ONLY the EventMetadata columns —
    NEVER `payload`. `cursor` is the exclusive lower bound on sequence_number (the monotonic
    PK); one extra row (limit+1) is fetched to compute the next cursor without a second query.
    `filters` may carry team_id / agent_id / event_type / since / until / tenant_id (a
    tenant_id filter only reaches here when it already equals the principal — the router 403s a
    mismatch — so it is redundant with RLS but applied harmlessly). Returns (rows, next_cursor)
    where next_cursor is the last returned row's sequence_number when more pages remain, else
    None.
    """
    conditions: list[str] = []
    params: dict[str, Any] = {}
    if cursor is not None:
        conditions.append("sequence_number > :cursor")
        params["cursor"] = cursor
    for column in ("tenant_id", "team_id", "agent_id", "event_type"):
        value = filters.get(column)
        if value is not None:
            conditions.append(f"{column} = :{column}")
            params[column] = value
    if filters.get("since") is not None:
        conditions.append("event_timestamp >= :since")
        params["since"] = filters["since"]
    if filters.get("until") is not None:
        conditions.append("event_timestamp < :until")
        params["until"] = filters["until"]
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    columns = ", ".join(_EVENT_METADATA_COLUMNS)
    params["lim"] = limit + 1
    # S608 safe: `columns` is joined from the constant _EVENT_METADATA_COLUMNS tuple and `where`
    # from literal predicate fragments — NO user input is interpolated into the SQL text; every
    # filter/cursor VALUE is a bound parameter.
    # avoid-sqlalchemy-text false positive: only the constant _EVENT_METADATA_COLUMNS tuple +
    # literal predicate fragments are interpolated; every filter/cursor VALUE is a bound parameter.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns}, sequence_number FROM ingest_events{where} "  # noqa: S608
        "ORDER BY sequence_number ASC LIMIT :lim"
    )
    result = await session.execute(statement, params)
    rows = result.mappings().all()
    next_cursor: int | None = None
    if len(rows) > limit:
        next_cursor = rows[limit - 1]["sequence_number"]
        rows = rows[:limit]
    projected = [{column: row[column] for column in _EVENT_METADATA_COLUMNS} for row in rows]
    return projected, next_cursor


async def list_dead_letters(
    session: AsyncSession,
    *,
    filters: dict[str, Any],
    limit: int,
    cursor: tuple[str, str] | None,
) -> tuple[list[dict[str, Any]], tuple[object, str] | None]:
    """Cursor-paginated, metadata-only read of dead_letter_queue (tenant session, RLS-scoped).

    Runs on get_tenant_session so RLS scopes rows to the principal's tenant AND hides
    NULL-tenant (payload-invalid, operator-only) rows from every tenant (NO explicit tenant
    predicate — the DB enforces isolation). Projects ONLY the DeadLetterMetadata columns —
    NEVER `original_envelope`. `cursor` is the exclusive lower bound on the composite
    (created_at, dlq_id) sort key; one extra row (limit+1) is fetched to compute the next
    cursor. `filters` may carry reason / source_product / since / until (since/until bound
    created_at — the index-aligned failure time). Returns (rows, next_cursor) where next_cursor
    is the last returned row's (created_at, dlq_id) when more pages remain, else None.
    """
    conditions: list[str] = []
    params: dict[str, Any] = {}
    if cursor is not None:
        c_created, c_dlq = cursor
        conditions.append("(created_at, dlq_id) > (CAST(:c_created AS timestamptz), :c_dlq)")
        params["c_created"] = c_created
        params["c_dlq"] = c_dlq
    for column in ("reason", "source_product"):
        value = filters.get(column)
        if value is not None:
            conditions.append(f"{column} = :{column}")
            params[column] = value
    if filters.get("since") is not None:
        conditions.append("created_at >= CAST(:since AS timestamptz)")
        params["since"] = filters["since"]
    if filters.get("until") is not None:
        conditions.append("created_at < CAST(:until AS timestamptz)")
        params["until"] = filters["until"]
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    columns = ", ".join(_DEAD_LETTER_METADATA_COLUMNS)
    params["lim"] = limit + 1
    # S608 safe: `columns` is joined from the constant _DEAD_LETTER_METADATA_COLUMNS tuple and
    # `where` from literal predicate fragments — NO user input is interpolated into the SQL text;
    # every filter/cursor VALUE is a bound parameter.
    # avoid-sqlalchemy-text false positive: only the constant _DEAD_LETTER_METADATA_COLUMNS tuple
    # + literal predicate fragments are interpolated; every filter/cursor VALUE is a bound param.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns}, created_at FROM dead_letter_queue{where} "  # noqa: S608
        "ORDER BY created_at ASC, dlq_id ASC LIMIT :lim"
    )
    result = await session.execute(statement, params)
    rows = result.mappings().all()
    next_cursor: tuple[object, str] | None = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = (last["created_at"], last["dlq_id"])
        rows = rows[:limit]
    projected = [{column: row[column] for column in _DEAD_LETTER_METADATA_COLUMNS} for row in rows]
    return projected, next_cursor
