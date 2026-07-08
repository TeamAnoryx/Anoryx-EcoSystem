"""Hash-chained, tamper-evident audit log for Delta's automated financial workflows (D-009).

Mirrors Anoryx-Sentinel's F-003 hash-chain design (``Anoryx-Sentinel/src/persistence/
hash_chain.py`` + ``audit_log_repository.py``), with one deliberate divergence documented
in ``docs/adr/0009-delta-financial-audit-chain.md`` Fork 1: Sentinel's chain is GLOBAL
across all tenants (its own cross-tenant security-event correlation needs that); every
other Delta financial table is already tenant-siloed by RLS, so this chain is PER-TENANT
instead. That keeps an audit append in the SAME tenant-scoped transaction as the business
write it records — Sentinel's own audit writes are a separate, later, privileged-session
transaction — a stronger guarantee here: a financial write and its audit row can never
diverge (no "business change committed but its audit row didn't" window).

Hash recipe (byte-precise, mirrors Sentinel's ``compute_row_hash``):
    GENESIS_HASH = SHA256("anoryx-delta:financial-audit:genesis:v1")   # hex, 64 chars
    row_hash = SHA256(canonical_json({
        tenant_id, entity_type, entity_id, action, actor,
        created_at (ISO 8601, UTC),
        prev_hash,
        note,            # opt-in-when-present: included ONLY when not None
    })).hexdigest()
    canonical_json(d) = json.dumps(d, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")

The opt-in-when-present rule for ``note`` (and any future optional column) mirrors
Sentinel's own rule (banked process rule #8): a field is hashed in iff the value is not
None, so adding a new optional column later never changes the canonical JSON — and
therefore never invalidates — any existing row's stored hash.

Concurrency: ``pg_advisory_xact_lock(hashtext(tenant_id))`` serializes the
tip-read -> insert critical section for one tenant (transaction-scoped, auto-released
at commit/rollback — mirrors Sentinel's global advisory lock, scoped down to one tenant
per lock key). Two different tenants essentially never contend on the same lock key; on
the rare hashtext collision the false serialization costs nothing but a wait, never a
correctness gap, since the tip read itself is still exact (WHERE tenant_id = ...).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import change_history

GENESIS_HASH = hashlib.sha256(b"anoryx-delta:financial-audit:genesis:v1").hexdigest()

# List-response bound (mirrors D-007's store.MAX_LIST_LIMIT / D-008's dashboards row cap).
MAX_LIST_LIMIT = 500

_CANONICAL_REQUIRED_FIELDS = (
    "tenant_id",
    "entity_type",
    "entity_id",
    "action",
    "actor",
    "created_at",
    "prev_hash",
)


def _canonical_json(data: dict) -> bytes:
    # str()-coerce every hashed field: every current caller already passes str, but
    # without this an app-layer bug that passed e.g. entity_id=5 (int) would hash the
    # JSON number 5 while every DB round-trip (the column is String(64)) reads back
    # the string "5" — a permanent, unrecoverable false "tampered" mismatch at verify
    # time for that row, not a real tamper.
    filtered = {k: str(data[k]) for k in _CANONICAL_REQUIRED_FIELDS}
    if data.get("note") is not None:
        filtered["note"] = str(data["note"])  # opt-in-when-present
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_row_hash(data: dict) -> str:
    """SHA-256 hex digest of the row's canonical JSON. ``prev_hash`` and ``created_at``
    are mandatory — a row can never be hashed without knowing its position in the chain."""
    for field in ("prev_hash", "created_at"):
        if field not in data:
            raise ValueError(f"compute_row_hash requires {field!r} in data")
    return hashlib.sha256(_canonical_json(data)).hexdigest()


@dataclass(frozen=True)
class HistoryRecord:
    history_id: str
    tenant_id: str
    entity_type: str
    entity_id: str
    action: str
    actor: str
    note: str | None
    created_at: datetime
    sequence_number: int
    prev_hash: str
    row_hash: str


@dataclass(frozen=True)
class ChainValidationResult:
    is_valid: bool
    rows_checked: int
    first_mismatch_sequence: int | None
    error_detail: str | None


def _row_hash_data(
    *,
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    action: str,
    actor: str,
    note,
    created_at,
    prev_hash: str,
) -> dict:
    return {
        "tenant_id": tenant_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "action": action,
        "actor": actor,
        "note": note,
        # Normalize to UTC before formatting: TIMESTAMPTZ round-trips through different
        # drivers with different tzinfo offsets for the SAME instant (e.g. a sync
        # migration connection's session TimeZone vs. asyncpg, which always returns
        # UTC) — isoformat() on an un-normalized value would hash a different string
        # for the identical point in time, desyncing a write's hash from a later
        # verify's recompute. Astimezone is a no-op when already UTC.
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
        "prev_hash": prev_hash,
    }


async def _tip_hash(session: AsyncSession, *, tenant_id: str) -> str:
    row = (
        await session.execute(
            select(change_history.c.row_hash)
            .where(change_history.c.tenant_id == tenant_id)
            .order_by(change_history.c.sequence_number.desc())
            .limit(1)
        )
    ).first()
    return GENESIS_HASH if row is None else row[0]


async def append_history(
    session: AsyncSession,
    *,
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    action: str,
    actor: str,
    now: datetime,
    note: str | None = None,
    history_id: str | None = None,
) -> HistoryRecord:
    """Append one hash-chained audit row for ``tenant_id``. Does NOT commit (caller owns
    the transaction — this can and should run in the SAME transaction as the business
    write it records, per this module's docstring Fork 1).

    Fail-closed by construction: the advisory lock + tip read + insert all happen inside
    the caller's already-open transaction, so a rollback of the business write also rolls
    back the audit row — there is no window where one commits without the other.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:t))"), {"t": tenant_id})
    prev_hash = await _tip_hash(session, tenant_id=tenant_id)

    hid = history_id or str(uuid.uuid4())
    row_hash = compute_row_hash(
        _row_hash_data(
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor=actor,
            note=note,
            created_at=now,
            prev_hash=prev_hash,
        )
    )
    result = await session.execute(
        change_history.insert()
        .values(
            history_id=hid,
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor=actor,
            note=note,
            created_at=now,
            prev_hash=prev_hash,
            row_hash=row_hash,
        )
        .returning(change_history.c.sequence_number)
    )
    sequence_number = result.scalar_one()

    return HistoryRecord(
        history_id=hid,
        tenant_id=tenant_id,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        actor=actor,
        note=note,
        created_at=now,
        sequence_number=sequence_number,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )


async def list_history(
    session: AsyncSession,
    *,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 100,
) -> list[HistoryRecord]:
    """List change-history rows for the caller's tenant (RLS-confined), newest first.

    ``limit`` is clamped to ``[1, MAX_LIST_LIMIT]`` (mirrors the D-007 pagination guard).
    """
    stmt = select(change_history)
    if entity_type is not None:
        stmt = stmt.where(change_history.c.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(change_history.c.entity_id == entity_id)
    stmt = stmt.order_by(change_history.c.created_at.desc()).limit(
        max(1, min(limit, MAX_LIST_LIMIT))
    )
    rows = (await session.execute(stmt)).all()
    return [
        HistoryRecord(
            history_id=r.history_id,
            tenant_id=r.tenant_id,
            entity_type=r.entity_type,
            entity_id=r.entity_id,
            action=r.action,
            actor=r.actor,
            note=r.note,
            created_at=r.created_at,
            sequence_number=r.sequence_number,
            prev_hash=r.prev_hash,
            row_hash=r.row_hash,
        )
        for r in rows
    ]


async def verify_chain(session: AsyncSession, *, tenant_id: str) -> ChainValidationResult:
    """Walk ``tenant_id``'s chain in order, recompute every hash, and report the first
    mismatch. Runs on the caller's tenant-scoped session — RLS confines it to exactly the
    rows an operator is authorized to see, which is also exactly the chain's own scope
    (per-tenant, see this module's docstring Fork 1) — no privileged session is needed,
    unlike Sentinel's global-chain verify.
    """
    stmt = (
        select(change_history)
        .where(change_history.c.tenant_id == tenant_id)
        .order_by(change_history.c.sequence_number)
    )
    rows = (await session.execute(stmt)).all()

    expected_prev = GENESIS_HASH
    checked = 0
    for row in rows:
        checked += 1
        if row.prev_hash != expected_prev:
            return ChainValidationResult(
                is_valid=False,
                rows_checked=checked,
                first_mismatch_sequence=row.sequence_number,
                error_detail=(
                    f"prev_hash mismatch at sequence_number={row.sequence_number}: "
                    f"expected {expected_prev}, stored {row.prev_hash}"
                ),
            )
        recomputed = compute_row_hash(
            _row_hash_data(
                tenant_id=row.tenant_id,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                action=row.action,
                actor=row.actor,
                note=row.note,
                created_at=row.created_at,
                prev_hash=row.prev_hash,
            )
        )
        if recomputed != row.row_hash:
            return ChainValidationResult(
                is_valid=False,
                rows_checked=checked,
                first_mismatch_sequence=row.sequence_number,
                error_detail=(
                    f"row_hash mismatch at sequence_number={row.sequence_number}: "
                    f"expected {recomputed}, stored {row.row_hash}"
                ),
            )
        expected_prev = row.row_hash

    return ChainValidationResult(
        is_valid=True, rows_checked=checked, first_mismatch_sequence=None, error_detail=None
    )
