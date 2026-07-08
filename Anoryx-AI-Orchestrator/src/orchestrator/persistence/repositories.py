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


# --------------------------------------------------------------------------- #
# Relay-dispatch audit chain (O-009, ADR-0009) — privileged session, no RLS.
# --------------------------------------------------------------------------- #

# Distinct transaction-scoped advisory-lock key for the relay-chain append (a stable
# bigint from a domain label, distinct from the ingest/distribution/registry keys).
_RELAY_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:relay-audit-chain").digest()[:8],
    "big",
    signed=True,
)


async def relay_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent relay_audit_log row_hash, or RELAY_GENESIS_HASH."""
    result = await session.execute(
        text("SELECT row_hash FROM relay_audit_log ORDER BY sequence_number DESC LIMIT 1")
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.RELAY_GENESIS_HASH


async def append_relay_audit_link(
    session: AsyncSession,
    *,
    tenant_id: str,
    source_product: str,
    sentinel_id: str,
    target_path: str,
    disposition: str,
    status_code: int | None = None,
    content_hash: str | None = None,
    error_reason: str | None = None,
) -> str:
    """Append one hash-chained relay_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. status_code/content_hash/
    error_reason follow the opt-in-when-present hash rule (hashed iff not None).
    """
    from orchestrator.persistence.models.relay_audit_log import RelayAuditLog

    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _RELAY_CHAIN_LOCK_KEY})
    prev_hash = await relay_chain_tip_hash(session)
    row = {
        "tenant_id": tenant_id,
        "source_product": source_product,
        "sentinel_id": sentinel_id,
        "target_path": target_path,
        "disposition": disposition,
        "status_code": status_code,
        "content_hash": content_hash,
        "error_reason": error_reason,
        "prev_hash": prev_hash,
    }
    row["row_hash"] = hash_chain.compute_relay_row_hash(row)
    await session.execute(insert(RelayAuditLog).values(**row))
    return row["row_hash"]


async def validate_relay_chain(session: AsyncSession) -> bool:
    """Re-validate the full relay-dispatch chain in order: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (the chain is global).

    FAIL-LOUD (mirrors validate_registry_chain, audit L-2): relay_audit_log carries no RLS,
    but a non-BYPASSRLS role lacks even SELECT here, so assert the role bypasses RLS first
    (a privileged session) rather than risk a vacuous pass over an empty/denied read.
    """
    from orchestrator.persistence.models.relay_audit_log import RelayAuditLog

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
            "validate_relay_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees a denied/empty read and would falsely report integrity."
        )
    result = await session.execute(
        select(RelayAuditLog).order_by(RelayAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.RELAY_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "tenant_id": row.tenant_id,
            "source_product": row.source_product,
            "sentinel_id": row.sentinel_id,
            "target_path": row.target_path,
            "disposition": row.disposition,
            "status_code": row.status_code,
            "content_hash": row.content_hash,
            "error_reason": row.error_reason,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_relay_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True


# --------------------------------------------------------------------------- #
# Identity-event correlation (O-010, ADR-0010) — data access (tenant session, RLS-scoped)
# and its audit chain (privileged session, no RLS).
# --------------------------------------------------------------------------- #

# The projection columns for both the tenant read and the admin cross-tenant read (identical
# shape — never any additional internal column beyond sequence_number, which is selected only
# to compute the tenant read's opaque cursor).
_IDENTITY_EVENT_COLUMNS = (
    "tenant_id",
    "source_product",
    "principal_type",
    "principal_id",
    "action",
    "target",
    "idempotency_key",
    "occurred_at",
    "received_at",
)


async def insert_identity_event(session: AsyncSession, row: dict[str, Any]) -> bool:
    """INSERT one identity_events row (tenant session, RLS-scoped). Caller commits.

    Idempotent: ON CONFLICT (source_product, idempotency_key) DO NOTHING. Returns True iff a
    NEW row was inserted, False iff the (source_product, idempotency_key) pair already
    existed (an idempotent replay — never a second row, never an error).
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from orchestrator.persistence.models.identity_event import IdentityEvent

    stmt = (
        pg_insert(IdentityEvent)
        .values(**row)
        .on_conflict_do_nothing(constraint="uq_ide_source_idempotency")
        .returning(IdentityEvent.sequence_number)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def list_identity_events(
    session: AsyncSession,
    *,
    filters: dict[str, Any],
    limit: int,
    cursor: int | None,
) -> tuple[list[dict[str, Any]], int | None]:
    """Cursor-paginated read of identity_events (tenant session, RLS-scoped).

    Runs on get_tenant_session so RLS scopes rows to the principal's tenant — no explicit
    tenant predicate. Mirrors O-006's list_events cursor discipline exactly: `cursor` is the
    exclusive lower bound on sequence_number; one extra row (limit+1) is fetched to compute
    the next cursor without a second query. `filters` may carry source_product/principal_type/
    action. Returns (rows, next_cursor).
    """
    conditions: list[str] = []
    params: dict[str, Any] = {}
    if cursor is not None:
        conditions.append("sequence_number > :cursor")
        params["cursor"] = cursor
    for column in ("source_product", "principal_type", "action"):
        value = filters.get(column)
        if value is not None:
            conditions.append(f"{column} = :{column}")
            params[column] = value
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    columns = ", ".join(_IDENTITY_EVENT_COLUMNS)
    params["lim"] = limit + 1
    # avoid-sqlalchemy-text false positive: `columns`/`where` are built from the constant
    # _IDENTITY_EVENT_COLUMNS tuple + literal predicate fragments; every VALUE is bound.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns}, sequence_number FROM identity_events{where} "  # noqa: S608
        "ORDER BY sequence_number ASC LIMIT :lim"
    )
    result = await session.execute(statement, params)
    rows = result.mappings().all()
    next_cursor: int | None = None
    if len(rows) > limit:
        next_cursor = rows[limit - 1]["sequence_number"]
        rows = rows[:limit]
    projected = [{column: row[column] for column in _IDENTITY_EVENT_COLUMNS} for row in rows]
    return projected, next_cursor


async def list_recent_identity_events_admin(
    session: AsyncSession, *, limit: int
) -> list[dict[str, Any]]:
    """Return the `limit` most-recent identity_events rows, newest first (PRIVILEGED session).

    Cross-tenant by design (operator fleet triage, mirrors ADR-0007's admin reads) — no
    tenant GUC, no RLS scoping. Same projection as the tenant-scoped read.
    """
    columns = ", ".join(_IDENTITY_EVENT_COLUMNS)
    # avoid-sqlalchemy-text false positive: `columns` is joined from the constant
    # _IDENTITY_EVENT_COLUMNS tuple; `limit` is a bound parameter, not interpolated.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns} FROM identity_events "  # noqa: S608
        "ORDER BY sequence_number DESC LIMIT :lim"
    )
    result = await session.execute(statement, {"lim": limit})
    rows = result.mappings().all()
    return [{column: row[column] for column in _IDENTITY_EVENT_COLUMNS} for row in rows]


# Distinct transaction-scoped advisory-lock key for the identity-chain append (a stable
# bigint from a domain label, distinct from every other chain's key).
_IDENTITY_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:identity-audit-chain").digest()[:8],
    "big",
    signed=True,
)


async def identity_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent identity_audit_log row_hash, or IDENTITY_GENESIS_HASH."""
    result = await session.execute(
        text("SELECT row_hash FROM identity_audit_log ORDER BY sequence_number DESC LIMIT 1")
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.IDENTITY_GENESIS_HASH


async def append_identity_audit_link(
    session: AsyncSession,
    *,
    tenant_id: str,
    source_product: str,
    principal_type: str,
    principal_id: str,
    action: str,
    idempotency_key: str,
    disposition: str,
    target: str | None = None,
) -> str:
    """Append one hash-chained identity_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. `target` follows the
    opt-in-when-present hash rule (hashed iff not None).
    """
    from orchestrator.persistence.models.identity_audit_log import IdentityAuditLog

    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _IDENTITY_CHAIN_LOCK_KEY})
    prev_hash = await identity_chain_tip_hash(session)
    row = {
        "tenant_id": tenant_id,
        "source_product": source_product,
        "principal_type": principal_type,
        "principal_id": principal_id,
        "action": action,
        "idempotency_key": idempotency_key,
        "disposition": disposition,
        "target": target,
        "prev_hash": prev_hash,
    }
    row["row_hash"] = hash_chain.compute_identity_row_hash(row)
    await session.execute(insert(IdentityAuditLog).values(**row))
    return row["row_hash"]


async def validate_identity_chain(session: AsyncSession) -> bool:
    """Re-validate the full identity-event chain in order: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (the chain is global).

    FAIL-LOUD (mirrors validate_relay_chain, audit L-2): identity_audit_log carries no RLS,
    but a non-BYPASSRLS role lacks even SELECT here, so assert the role bypasses RLS first
    (a privileged session) rather than risk a vacuous pass over an empty/denied read.
    """
    from orchestrator.persistence.models.identity_audit_log import IdentityAuditLog

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
            "validate_identity_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees a denied/empty read and would falsely report integrity."
        )
    result = await session.execute(
        select(IdentityAuditLog).order_by(IdentityAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.IDENTITY_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "tenant_id": row.tenant_id,
            "source_product": row.source_product,
            "principal_type": row.principal_type,
            "principal_id": row.principal_id,
            "action": row.action,
            "idempotency_key": row.idempotency_key,
            "disposition": row.disposition,
            "target": row.target,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_identity_row_hash(row_data, row.row_hash):
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


# =========================================================================== #
# Admin API read seams (O-007, ADR-0007) — ADDITIVE, parallel to the blocks above. The
# operator (ORCH_ADMIN_TOKEN, same principal as the O-005 registry) gets bounded,
# metadata-only, CROSS-TENANT visibility for fleet triage — deliberately coarser than the
# O-006 per-tenant reads, mirroring the registry's own operator-global scope. Both reads run
# on the caller-owned PRIVILEGED session (no tenant GUC, so no RLS scoping applies) and
# project ONLY metadata columns — never `payload`, never `signed_record`. "Recent" is a
# single DESC-ordered, Limit-bounded page — no cursor (out of scope; see ADR-0007).
# =========================================================================== #

# Mirrors _EVENT_METADATA_COLUMNS (O-006) — identical projection, cross-tenant scope only.
_ADMIN_EVENT_METADATA_COLUMNS = _EVENT_METADATA_COLUMNS

# The AdminDistributionSummary projection columns (openapi.yaml). Deliberately excludes
# `signed_record` / `content_hash` (never re-expose a policy body on a fleet-overview read).
_ADMIN_DISTRIBUTION_SUMMARY_COLUMNS = (
    "distribution_id",
    "policy_id",
    "tenant_id",
    "policy_type",
    "state",
    "created_at",
)


async def list_recent_events_admin(session: AsyncSession, *, limit: int) -> list[dict[str, Any]]:
    """Return the `limit` most-recent ingest_events rows, newest first (PRIVILEGED session).

    Cross-tenant by design (operator fleet triage, ADR-0007) — no tenant GUC, no RLS
    scoping. Projects ONLY the EventMetadata columns, identical to the O-006 `list_events`
    projection — never `payload`.
    """
    columns = ", ".join(_ADMIN_EVENT_METADATA_COLUMNS)
    # avoid-sqlalchemy-text false positive: `columns` is joined from the constant
    # _ADMIN_EVENT_METADATA_COLUMNS tuple; `limit` is a bound parameter, not interpolated.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns} FROM ingest_events "  # noqa: S608
        "ORDER BY sequence_number DESC LIMIT :lim"
    )
    result = await session.execute(statement, {"lim": limit})
    rows = result.mappings().all()
    return [{column: row[column] for column in _ADMIN_EVENT_METADATA_COLUMNS} for row in rows]


async def append_automation_audit_link(
    session: AsyncSession,
    *,
    rule_id: str,
    tenant_id: str,
    triggering_event_id: str,
    action_type: str,
    disposition: str,
    error_reason: str | None = None,
) -> str:
    """Append one hash-chained automation_executions link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. error_reason follows the
    opt-in-when-present hash rule (hashed iff not None).

    UNIQUE(rule_id, triggering_event_id) may raise IntegrityError on the INSERT below —
    the CALLER catches it narrowly as the idempotency dedup gate: a retried/duplicate
    schedule of the same accepted ingest event's automation evaluation is treated as
    "already executed, skip", never as an error (mirrors the ingest pipeline's own
    narrow-IntegrityError dedup discipline).
    """
    from orchestrator.persistence.models.automation_execution import AutomationExecution

    await session.execute(
        text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUTOMATION_CHAIN_LOCK_KEY}
    )
    prev_hash = await automation_chain_tip_hash(session)
    row = {
        "rule_id": rule_id,
        "tenant_id": tenant_id,
        "triggering_event_id": triggering_event_id,
        "action_type": action_type,
        "disposition": disposition,
        "error_reason": error_reason,
        "prev_hash": prev_hash,
    }
    row["row_hash"] = hash_chain.compute_automation_row_hash(row)
    await session.execute(insert(AutomationExecution).values(**row))
    return row["row_hash"]


# Distinct transaction-scoped advisory-lock key for the automation-chain append (a stable
# bigint from a domain label, distinct from every other chain's key).
_AUTOMATION_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:automation-audit-chain").digest()[:8],
    "big",
    signed=True,
)


async def automation_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent automation_executions row_hash, or AUTOMATION_GENESIS_HASH."""
    result = await session.execute(
        text("SELECT row_hash FROM automation_executions ORDER BY sequence_number DESC LIMIT 1")
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.AUTOMATION_GENESIS_HASH


async def validate_automation_chain(session: AsyncSession) -> bool:
    """Re-validate the full automation-execution chain: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (the chain is global).

    FAIL-LOUD (mirrors validate_identity_chain, audit L-2): automation_executions carries
    RLS (unlike relay/identity), but a non-BYPASSRLS role would only see its own tenant's
    rows, so assert the role bypasses RLS first (a privileged session) rather than risk a
    partial-chain false pass.
    """
    from orchestrator.persistence.models.automation_execution import AutomationExecution

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
            "validate_automation_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees an RLS-scoped subset and would falsely report integrity."
        )
    result = await session.execute(
        select(AutomationExecution).order_by(AutomationExecution.sequence_number.asc())
    )
    expected_prev = hash_chain.AUTOMATION_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "rule_id": row.rule_id,
            "tenant_id": row.tenant_id,
            "triggering_event_id": row.triggering_event_id,
            "action_type": row.action_type,
            "disposition": row.disposition,
            "error_reason": row.error_reason,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_automation_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True


# --------------------------------------------------------------------------- #
# Automation-rules CRUD (O-011, ADR-0011) — tenant session (RLS-scoped).
# --------------------------------------------------------------------------- #

_AUTOMATION_RULE_COLUMNS = (
    "id",
    "tenant_id",
    "name",
    "enabled",
    "trigger_event_type",
    "trigger_source_product",
    "trigger_conditions",
    "action_type",
    "action_config",
    "created_at",
    "updated_at",
)


async def insert_automation_rule(session: AsyncSession, row: dict[str, Any]) -> dict[str, Any]:
    """INSERT one automation_rules row (tenant session, RLS-scoped) and return the full
    persisted row (including server-defaulted created_at/updated_at). Caller commits.

    May raise IntegrityError on UNIQUE(tenant_id, name) — the router catches it narrowly
    and returns 409 (duplicate rule name), never a 5xx.
    """
    from orchestrator.persistence.models.automation_rule import AutomationRule

    stmt = insert(AutomationRule).values(**row).returning(AutomationRule)
    result = await session.execute(stmt)
    inserted = result.scalar_one()
    return {c.name: getattr(inserted, c.name) for c in AutomationRule.__table__.columns}


# Distinct transaction-scoped advisory-lock NAMESPACE for the per-tenant rule-cap lock
# (TOCTOU fix, code-reviewer + security-auditor O-011 follow-up). This uses the pg
# pg_advisory_xact_lock(int, int) TWO-ARG overload — a fixed namespace plus a per-tenant
# hashtext(...) key — which is a DIFFERENT PostgreSQL function overload from the
# single-bigint pg_advisory_xact_lock(:k) form every chain-append lock above uses
# (_CHAIN_LOCK_KEY / _DISTRIBUTION_CHAIN_LOCK_KEY / _REGISTRY_CHAIN_LOCK_KEY /
# _RELAY_CHAIN_LOCK_KEY / _IDENTITY_CHAIN_LOCK_KEY / _AUTOMATION_CHAIN_LOCK_KEY), so this
# lock can never collide with any of those fixed-key chain-append locks.
_AUTOMATION_RULE_CAP_LOCK_NAMESPACE = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:automation-rule-cap").digest()[:4],
    "big",
    signed=True,
)


async def lock_automation_rule_cap(session: AsyncSession, tenant_id: str) -> None:
    """Take a transaction-scoped, PER-TENANT advisory lock before the rule-cap COUNT.

    Closes a TOCTOU race: concurrent `POST /v1/automation/rules` requests for the SAME
    tenant, with DISTINCT rule names (so UNIQUE(tenant_id, name) does not serialise them),
    could otherwise both COUNT before either INSERTs, racing past
    ORCH_AUTOMATION_MAX_RULES_PER_TENANT. Locking PER TENANT (via `hashtext(tenant_id)`,
    not a single fixed key) means concurrent creates for DIFFERENT tenants never contend
    with each other. The caller MUST call this INSIDE the same transaction as the
    subsequent COUNT + INSERT (the lock auto-releases at COMMIT/ROLLBACK) — never wrapped
    in its own `session.begin()` (the tenant session already autobegins).
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:ns, hashtext(:tenant_id))"),
        {"ns": _AUTOMATION_RULE_CAP_LOCK_NAMESPACE, "tenant_id": tenant_id},
    )


async def count_automation_rules(session: AsyncSession) -> int:
    """Count this tenant's automation_rules rows (tenant session, RLS-scoped).

    Used at rule-creation time to enforce the per-tenant cap
    (ORCH_AUTOMATION_MAX_RULES_PER_TENANT) BEFORE the insert — exceeding it is a 422
    `rule_limit_exceeded`, never a 5xx. The caller takes `lock_automation_rule_cap` in the
    SAME transaction immediately before calling this, so a concurrent creator for the same
    tenant can never COUNT a stale value and race past the cap (TOCTOU fix).
    """
    result = await session.execute(text("SELECT count(*) FROM automation_rules"))
    return int(result.scalar_one())


async def get_automation_rule(session: AsyncSession, rule_id: str) -> dict[str, Any] | None:
    """Return one automation_rules row as a dict, or None (tenant session, RLS-scoped).

    RLS makes another tenant's row invisible here (a 404, never a 403, at the router).
    """
    from orchestrator.persistence.models.automation_rule import AutomationRule

    result = await session.execute(select(AutomationRule).where(AutomationRule.id == rule_id))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in AutomationRule.__table__.columns}


async def list_automation_rules(
    session: AsyncSession,
    *,
    limit: int,
    cursor: tuple[object, str] | None,
) -> tuple[list[dict[str, Any]], tuple[object, str] | None]:
    """Cursor-paginated read of this tenant's automation_rules (tenant session, RLS-scoped).

    Mirrors list_dead_letters' composite (created_at, id) cursor discipline: `cursor` is
    the exclusive lower bound on that composite sort key; one extra row (limit+1) is
    fetched to compute the next cursor without a second query.
    """
    conditions: list[str] = []
    params: dict[str, Any] = {}
    if cursor is not None:
        c_created, c_id = cursor
        conditions.append("(created_at, id) > (CAST(:c_created AS timestamptz), :c_id)")
        params["c_created"] = c_created
        params["c_id"] = c_id
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    columns = ", ".join(_AUTOMATION_RULE_COLUMNS)
    params["lim"] = limit + 1
    # avoid-sqlalchemy-text false positive: `columns`/`where` are built from the constant
    # _AUTOMATION_RULE_COLUMNS tuple + literal predicate fragments; every VALUE is bound.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns} FROM automation_rules{where} "  # noqa: S608
        "ORDER BY created_at ASC, id ASC LIMIT :lim"
    )
    result = await session.execute(statement, params)
    rows = result.mappings().all()
    next_cursor: tuple[object, str] | None = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = (last["created_at"], last["id"])
        rows = rows[:limit]
    projected = [{column: row[column] for column in _AUTOMATION_RULE_COLUMNS} for row in rows]
    return projected, next_cursor


async def update_automation_rule_enabled(
    session: AsyncSession, *, rule_id: str, enabled: bool
) -> int:
    """UPDATE one automation_rules row's `enabled` flag (tenant session, RLS-scoped).

    Returns rowcount (0 -> the router 404s: unknown id or another tenant's row, RLS-hidden).
    Caller commits. `updated_at` is always stamped.
    """
    from sqlalchemy import update

    from orchestrator.persistence.models.automation_rule import AutomationRule

    result = await session.execute(
        update(AutomationRule)
        .where(AutomationRule.id == rule_id)
        .values(enabled=enabled, updated_at=datetime.now(timezone.utc))
    )
    return result.rowcount


async def delete_automation_rule(session: AsyncSession, rule_id: str) -> int:
    """DELETE one automation_rules row (tenant session, RLS-scoped). Returns rowcount.

    Caller commits. A rowcount of 0 -> the router 404s (unknown id or RLS-hidden).
    """
    from sqlalchemy import delete

    from orchestrator.persistence.models.automation_rule import AutomationRule

    result = await session.execute(delete(AutomationRule).where(AutomationRule.id == rule_id))
    return result.rowcount


async def list_enabled_automation_rules(
    session: AsyncSession, *, tenant_id: str, event_type: str
) -> list[dict[str, Any]]:
    """Return this tenant's ENABLED automation_rules matching *event_type* (tenant session,
    RLS-scoped).

    tenant_id is applied as an explicit, REDUNDANT-with-RLS filter (mirrors list_events'
    identical precedent: harmless, since RLS already scopes the session to this tenant).
    Bounded by the per-tenant rule cap already enforced at creation time
    (ORCH_AUTOMATION_MAX_RULES_PER_TENANT), so this is never an unbounded per-event scan.
    """
    from orchestrator.persistence.models.automation_rule import AutomationRule

    result = await session.execute(
        select(AutomationRule).where(
            AutomationRule.tenant_id == tenant_id,
            AutomationRule.enabled.is_(True),
            AutomationRule.trigger_event_type == event_type,
        )
    )
    return [
        {c.name: getattr(row, c.name) for c in AutomationRule.__table__.columns}
        for row in result.scalars()
    ]


# --------------------------------------------------------------------------- #
# Automation-executions read (O-011, ADR-0011) — tenant session, RLS-scoped SELECT.
# --------------------------------------------------------------------------- #

_AUTOMATION_EXECUTION_COLUMNS = (
    "rule_id",
    "tenant_id",
    "triggering_event_id",
    "action_type",
    "disposition",
    "error_reason",
    "created_at",
)


async def list_automation_executions(
    session: AsyncSession,
    *,
    limit: int,
    cursor: int | None,
) -> tuple[list[dict[str, Any]], int | None]:
    """Cursor-paginated, tenant-scoped read of automation_executions (tenant session).

    automation_executions carries RLS SELECT-scoping (unlike relay/identity's chains,
    which have none) — this read runs on get_tenant_session so RLS structurally scopes it
    to the caller's own tenant. `cursor` is the exclusive lower bound on sequence_number;
    one extra row (limit+1) is fetched to compute the next cursor without a second query.
    """
    conditions: list[str] = []
    params: dict[str, Any] = {}
    if cursor is not None:
        conditions.append("sequence_number > :cursor")
        params["cursor"] = cursor
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    columns = ", ".join(_AUTOMATION_EXECUTION_COLUMNS)
    params["lim"] = limit + 1
    # avoid-sqlalchemy-text false positive: `columns`/`where` are built from the constant
    # _AUTOMATION_EXECUTION_COLUMNS tuple + literal predicate fragments; every VALUE is bound.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns}, sequence_number FROM automation_executions{where} "  # noqa: S608
        "ORDER BY sequence_number ASC LIMIT :lim"
    )
    result = await session.execute(statement, params)
    rows = result.mappings().all()
    next_cursor: int | None = None
    if len(rows) > limit:
        next_cursor = rows[limit - 1]["sequence_number"]
        rows = rows[:limit]
    projected = [{column: row[column] for column in _AUTOMATION_EXECUTION_COLUMNS} for row in rows]
    return projected, next_cursor


async def list_recent_distributions_admin(
    session: AsyncSession, *, limit: int
) -> list[dict[str, Any]]:
    """Return the `limit` most-recent policy_distributions rows, newest first (PRIVILEGED).

    Cross-tenant by design (operator fleet triage, ADR-0007) — no tenant GUC, no RLS
    scoping. Projects ONLY the AdminDistributionSummary columns — never `signed_record` /
    `content_hash` (no policy body on a fleet-overview read). Per-target detail is NOT
    included here; an operator drills into a specific distribution via the existing
    coarse-relay `GET /v1/policies/distributions/{distribution_id}` (O-004/O-006) for that.
    """
    columns = ", ".join(_ADMIN_DISTRIBUTION_SUMMARY_COLUMNS)
    # avoid-sqlalchemy-text false positive: `columns` is joined from the constant
    # _ADMIN_DISTRIBUTION_SUMMARY_COLUMNS tuple; `limit` is a bound parameter.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns} FROM policy_distributions "  # noqa: S608
        "ORDER BY created_at DESC LIMIT :lim"
    )
    result = await session.execute(statement, {"lim": limit})
    rows = result.mappings().all()
    return [{column: row[column] for column in _ADMIN_DISTRIBUTION_SUMMARY_COLUMNS} for row in rows]


# =========================================================================== #
# Agent mailbox relay (O-012, ADR-0012) — data access (tenant session, RLS-scoped) and its
# audit chain (privileged session, no RLS on writes; RLS-scoped SELECT, mirrors
# automation_executions).
# =========================================================================== #

_AGENT_MESSAGE_COLUMNS = (
    "sequence_number",
    "tenant_id",
    "sender_team_id",
    "sender_project_id",
    "sender_agent_id",
    "recipient_team_id",
    "recipient_project_id",
    "recipient_agent_id",
    "message_type",
    "body",
    "idempotency_key",
    "created_at",
)


async def insert_agent_message(session: AsyncSession, row: dict[str, Any]) -> dict[str, Any]:
    """INSERT one agent_messages row (tenant session, RLS-scoped) and return the full
    persisted row (including the server-assigned sequence_number/created_at). Caller commits.

    May raise IntegrityError on UNIQUE(tenant_id, idempotency_key) — the router catches it
    NARROWLY (mirrors the O-003 ingest pipeline's own dedup discipline), rolls back, and
    re-fetches the ORIGINAL row via `get_agent_message_by_idempotency_key` on a FRESH tenant
    session (a rolled-back session's transaction-local tenant GUC is gone — reusing it here
    would run the re-read with no tenant context set, mirroring automation/router.py's PATCH
    two-separate-sessions precedent).
    """
    from orchestrator.persistence.models.agent_message import AgentMessage

    stmt = insert(AgentMessage).values(**row).returning(AgentMessage)
    result = await session.execute(stmt)
    inserted = result.scalar_one()
    return {c.name: getattr(inserted, c.name) for c in AgentMessage.__table__.columns}


async def get_agent_message_by_idempotency_key(
    session: AsyncSession, idempotency_key: str
) -> dict[str, Any] | None:
    """Return one agent_messages row by idempotency_key, or None (tenant session, RLS-scoped).

    Used to re-fetch the ORIGINAL message after a dedup IntegrityError on insert — the
    UNIQUE(tenant_id, idempotency_key) constraint means a conflict can only ever be with a
    row of the caller's OWN tenant, so this RLS-scoped lookup always finds it.
    """
    from orchestrator.persistence.models.agent_message import AgentMessage

    result = await session.execute(
        select(AgentMessage).where(AgentMessage.idempotency_key == idempotency_key)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in AgentMessage.__table__.columns}


async def list_inbox_messages(
    session: AsyncSession,
    *,
    team_id: str,
    project_id: str,
    agent_id: str,
    since_sequence: int | None,
    limit: int,
) -> tuple[list[dict[str, Any]], int | None]:
    """Cursor-paginated read of one agent's inbox (tenant session, RLS-scoped).

    Returns messages addressed to (team_id, project_id, agent_id), ordered by
    sequence_number ASCENDING. `since_sequence` is the EXCLUSIVE lower bound (mirrors every
    other cursor discipline in this module); one extra row (limit+1) is fetched to compute
    the next cursor without a second query. RLS means a tenant can only ever poll inboxes
    for agents within ITS OWN tenant — there is no separate cross-tenant check needed.
    """
    conditions = [
        "recipient_team_id = :team_id",
        "recipient_project_id = :project_id",
        "recipient_agent_id = :agent_id",
    ]
    params: dict[str, Any] = {"team_id": team_id, "project_id": project_id, "agent_id": agent_id}
    if since_sequence is not None:
        conditions.append("sequence_number > :since_sequence")
        params["since_sequence"] = since_sequence
    where = " WHERE " + " AND ".join(conditions)
    columns = ", ".join(_AGENT_MESSAGE_COLUMNS)
    params["lim"] = limit + 1
    # avoid-sqlalchemy-text false positive: `columns`/`where` are built from the constant
    # _AGENT_MESSAGE_COLUMNS tuple + literal predicate fragments; every VALUE is bound.
    # nosemgrep: avoid-sqlalchemy-text
    statement = text(
        f"SELECT {columns} FROM agent_messages{where} "  # noqa: S608
        "ORDER BY sequence_number ASC LIMIT :lim"
    )
    result = await session.execute(statement, params)
    rows = result.mappings().all()
    next_cursor: int | None = None
    if len(rows) > limit:
        next_cursor = rows[limit - 1]["sequence_number"]
        rows = rows[:limit]
    projected = [{column: row[column] for column in _AGENT_MESSAGE_COLUMNS} for row in rows]
    return projected, next_cursor


# Distinct transaction-scoped advisory-lock key for the messaging-chain append (a stable
# bigint from a domain label, distinct from every other chain's key).
_MESSAGING_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:messaging-audit-chain").digest()[:8],
    "big",
    signed=True,
)


async def messaging_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent agent_messaging_audit_log row_hash, or MESSAGING_GENESIS_HASH."""
    result = await session.execute(
        text(
            "SELECT row_hash FROM agent_messaging_audit_log "
            "ORDER BY sequence_number DESC LIMIT 1"
        )
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.MESSAGING_GENESIS_HASH


async def append_messaging_audit_link(
    session: AsyncSession,
    *,
    tenant_id: str,
    sender_agent_id: str,
    recipient_agent_id: str,
    message_type: str,
    idempotency_key: str,
    disposition: str,
) -> str:
    """Append one hash-chained agent_messaging_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. Records every send ATTEMPT —
    both 'sent' and 'deduped' get a link (ADR-0012; contrast with append_state_audit_link
    below, which mirrors O-011's "only the meaningful outcome" semantics instead).
    """
    from orchestrator.persistence.models.agent_messaging_audit_log import AgentMessagingAuditLog

    await session.execute(
        text("SELECT pg_advisory_xact_lock(:k)"), {"k": _MESSAGING_CHAIN_LOCK_KEY}
    )
    prev_hash = await messaging_chain_tip_hash(session)
    row = {
        "tenant_id": tenant_id,
        "sender_agent_id": sender_agent_id,
        "recipient_agent_id": recipient_agent_id,
        "message_type": message_type,
        "idempotency_key": idempotency_key,
        "disposition": disposition,
        "prev_hash": prev_hash,
    }
    row["row_hash"] = hash_chain.compute_messaging_row_hash(row)
    await session.execute(insert(AgentMessagingAuditLog).values(**row))
    return row["row_hash"]


async def validate_messaging_chain(session: AsyncSession) -> bool:
    """Re-validate the full agent-messaging chain: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (mirrors
    validate_automation_chain's FAIL-LOUD BYPASSRLS assertion: this chain carries RLS, so a
    non-bypass role would only see its own tenant's rows and could falsely report integrity).
    """
    from orchestrator.persistence.models.agent_messaging_audit_log import AgentMessagingAuditLog

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
            "validate_messaging_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees an RLS-scoped subset and would falsely report integrity."
        )
    result = await session.execute(
        select(AgentMessagingAuditLog).order_by(AgentMessagingAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.MESSAGING_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "tenant_id": row.tenant_id,
            "sender_agent_id": row.sender_agent_id,
            "recipient_agent_id": row.recipient_agent_id,
            "message_type": row.message_type,
            "idempotency_key": row.idempotency_key,
            "disposition": row.disposition,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_messaging_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True


# =========================================================================== #
# Shared state store (O-012, ADR-0012) — data access (tenant session, RLS-scoped) and its
# audit chain (privileged session, RLS-scoped SELECT, mirrors automation_executions).
# =========================================================================== #


async def get_agent_state(session: AsyncSession, state_key: str) -> dict[str, Any] | None:
    """Return one agent_state row as a dict, or None (tenant session, RLS-scoped)."""
    from orchestrator.persistence.models.agent_state import AgentState

    result = await session.execute(select(AgentState).where(AgentState.state_key == state_key))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in AgentState.__table__.columns}


async def create_agent_state_if_absent(
    session: AsyncSession,
    *,
    tenant_id: str,
    state_key: str,
    state_value: dict[str, Any],
    updated_by_agent_id: str | None,
) -> dict[str, Any] | None:
    """INSERT a new agent_state row iff (tenant_id, state_key) is absent (tenant session).

    ON CONFLICT DO NOTHING is the atomic, race-safe "create-only-if-absent" primitive — two
    concurrent creates for the SAME key can never both succeed (the UNIQUE constraint lets
    exactly one INSERT win; the loser's RETURNING is empty, never an IntegrityError). Returns
    the newly created row (version=1) iff THIS call won the race, else None — the caller then
    reads back the current row (`get_agent_state`) to echo its version in a 409
    `already_exists`. Caller commits.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from orchestrator.persistence.models.agent_state import AgentState

    stmt = (
        pg_insert(AgentState)
        .values(
            tenant_id=tenant_id,
            state_key=state_key,
            state_value=state_value,
            updated_by_agent_id=updated_by_agent_id,
        )
        .on_conflict_do_nothing(constraint="uq_as_tenant_state_key")
        .returning(AgentState)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in AgentState.__table__.columns}


async def update_agent_state_cas(
    session: AsyncSession,
    *,
    state_key: str,
    expected_version: int,
    state_value: dict[str, Any],
    updated_by_agent_id: str | None,
) -> dict[str, Any] | None:
    """Atomically UPDATE one agent_state row iff its CURRENT version == expected_version.

    `UPDATE ... WHERE state_key = :k AND version = :expected` (RLS's own USING/WITH CHECK
    predicate additionally confines this to the caller's tenant) is the race-safe CAS idiom
    — no separate lock statement is needed: under Postgres's MVCC, two concurrent writers
    racing on the SAME (tenant_id, state_key) with the SAME expected_version serialise on the
    row's write lock, and the second writer's WHERE clause re-evaluates against the
    already-committed new version and genuinely fails to match (never a silent overwrite).
    Returns the UPDATED row (new version) iff this call's CAS won, else None (the caller
    then reads back the current row to echo its version in a 409 `version_conflict`). Caller
    commits.
    """
    from sqlalchemy import update

    from orchestrator.persistence.models.agent_state import AgentState

    stmt = (
        update(AgentState)
        .where(AgentState.state_key == state_key, AgentState.version == expected_version)
        .values(
            state_value=state_value,
            version=AgentState.version + 1,
            updated_at=datetime.now(timezone.utc),
            updated_by_agent_id=updated_by_agent_id,
        )
        .returning(AgentState)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return {c.name: getattr(row, c.name) for c in AgentState.__table__.columns}


# Distinct transaction-scoped advisory-lock key for the state-chain append (a stable
# bigint from a domain label, distinct from every other chain's key).
_STATE_CHAIN_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"anoryx-orchestrator:state-audit-chain").digest()[:8],
    "big",
    signed=True,
)


async def state_chain_tip_hash(session: AsyncSession) -> str:
    """Return the most-recent agent_state_audit_log row_hash, or STATE_GENESIS_HASH."""
    result = await session.execute(
        text("SELECT row_hash FROM agent_state_audit_log ORDER BY sequence_number DESC LIMIT 1")
    )
    tip = result.scalar_one_or_none()
    return tip if tip is not None else hash_chain.STATE_GENESIS_HASH


async def append_state_audit_link(
    session: AsyncSession,
    *,
    tenant_id: str,
    state_key: str,
    version: int,
    disposition: str,
    updated_by_agent_id: str | None = None,
) -> str:
    """Append one hash-chained agent_state_audit_log link (privileged session).

    Caller opens the privileged transaction (`async with session.begin()`). A
    transaction-scoped advisory lock (own key) serialises concurrent appends so prev_hash
    always references the true tip. Returns the new row_hash. Mirrors O-011's
    automation_executions "only the meaningful outcome" semantics — the CALLER must only
    invoke this for a genuine 'created'/'updated' write, NEVER for a version-conflict
    rejection (nothing about the stored state changed, so there is nothing tamper-evident
    to record; see append_messaging_audit_link above for the messaging chain's OPPOSITE
    "every attempt" choice, and ADR-0012 for why the two chains differ).
    """
    from orchestrator.persistence.models.agent_state_audit_log import AgentStateAuditLog

    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _STATE_CHAIN_LOCK_KEY})
    prev_hash = await state_chain_tip_hash(session)
    row = {
        "tenant_id": tenant_id,
        "state_key": state_key,
        "version": version,
        "updated_by_agent_id": updated_by_agent_id,
        "disposition": disposition,
        "prev_hash": prev_hash,
    }
    row["row_hash"] = hash_chain.compute_state_row_hash(row)
    await session.execute(insert(AgentStateAuditLog).values(**row))
    return row["row_hash"]


async def validate_state_chain(session: AsyncSession) -> bool:
    """Re-validate the full shared-state chain: each row_hash recomputes + links.

    Returns True iff every link verifies. O(n) — privileged session (mirrors
    validate_automation_chain's FAIL-LOUD BYPASSRLS assertion: this chain carries RLS, so a
    non-bypass role would only see its own tenant's rows and could falsely report integrity).
    """
    from orchestrator.persistence.models.agent_state_audit_log import AgentStateAuditLog

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
            "validate_state_chain requires a BYPASSRLS/superuser privileged session; a "
            "non-bypass role sees an RLS-scoped subset and would falsely report integrity."
        )
    result = await session.execute(
        select(AgentStateAuditLog).order_by(AgentStateAuditLog.sequence_number.asc())
    )
    expected_prev = hash_chain.STATE_GENESIS_HASH
    for row in result.scalars():
        if row.prev_hash != expected_prev:
            return False
        row_data = {
            "tenant_id": row.tenant_id,
            "state_key": row.state_key,
            "version": row.version,
            "updated_by_agent_id": row.updated_by_agent_id,
            "disposition": row.disposition,
            "prev_hash": row.prev_hash,
        }
        if not hash_chain.verify_state_row_hash(row_data, row.row_hash):
            return False
        expected_prev = row.row_hash
    return True
