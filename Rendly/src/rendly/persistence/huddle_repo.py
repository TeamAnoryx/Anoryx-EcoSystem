"""Huddle session-record archiving (R-009) — the DB home for the archival half ADR-0007 (R-007)
deliberately left ephemeral ("R-009 owns... persisting the session record").

Only a TERMINAL ``ended`` session is archived — a ``declined`` ring never connects and carries
no session content, and the wire contract itself only attaches ``archival`` once a huddle
"reaches a durable (ended) state" (``contracts/messages.schema.json`` ``HuddleUpdate``).

ORDERING: mirrors ``chat_repo.insert_message``'s per-channel row-lock pattern, but scoped per
TENANT (``ArchivalMeta.seq``: "Monotonic... per-tenant (huddles) ordering sequence") via
``huddle_chain_state`` — the huddle analog of ``channels.next_seq``/``last_row_hash``: one row
per tenant, lazily upserted on that tenant's first archived huddle, locked with
``SELECT ... FOR UPDATE`` to serialize concurrent archive writes for the SAME tenant and
read/advance the chain tip under that lock.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..realtime.huddle import HuddleArchive
from . import hash_chain
from .chat_models import HuddleChainStateRow, HuddleRow


async def archive_ended_huddle(
    session: AsyncSession,
    *,
    tenant_id: str,
    huddle_id: str,
    caller_id: str,
    callee_id: str,
    created_at: datetime,
    ended_at: datetime,
) -> HuddleArchive:
    """Persist the terminal session record for an ENDED huddle, chained per tenant.

    Lazily upserts + locks this tenant's ``huddle_chain_state`` row, assigns the next
    per-tenant ``seq``, chains ``content_hash`` from the tenant's current tip (or the
    ``HUDDLE_GENESIS_HASH`` for that tenant's first-ever archived huddle), inserts the
    APPEND-ONLY ``huddles`` row, and advances the tip. The caller commits (mirrors every other
    write helper in this module family — ``chat_repo.insert_message``,
    ``chat_repo.insert_inspection_audit``).
    """
    # Lazily seed the tenant's chain-state row (idempotent no-op if it already exists) so the
    # very first archived huddle for a tenant has a row to lock. ON CONFLICT DO NOTHING is safe
    # under concurrent first-archives: the loser's INSERT is a no-op, then it locks the
    # winner's row normally via the SELECT ... FOR UPDATE below.
    await session.execute(
        pg_insert(HuddleChainStateRow)
        .values(tenant_id=tenant_id, next_seq=0, last_row_hash=None)
        .on_conflict_do_nothing(index_elements=["tenant_id"])
    )
    tip = (
        await session.execute(
            select(HuddleChainStateRow)
            .where(HuddleChainStateRow.tenant_id == tenant_id)
            .with_for_update()
        )
    ).scalar_one()

    seq = tip.next_seq
    prev_hash = tip.last_row_hash or hash_chain.HUDDLE_GENESIS_HASH
    hash_fields = {
        "tenant_id": tenant_id,
        "huddle_id": huddle_id,
        "caller_id": caller_id,
        "callee_id": callee_id,
        "state": "ended",
        "seq": seq,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
        "ended_at": ended_at.astimezone(timezone.utc).isoformat(),
        "prev_record_hash": prev_hash,
    }
    content_hash = hash_chain.compute_row_hash(hash_fields, hash_chain.HUDDLE_CANONICAL_FIELDS)

    session.add(
        HuddleRow(
            tenant_id=tenant_id,
            huddle_id=huddle_id,
            caller_id=caller_id,
            callee_id=callee_id,
            state="ended",
            seq=seq,
            created_at=created_at,
            ended_at=ended_at,
            prev_record_hash=prev_hash,
            content_hash=content_hash,
        )
    )
    tip.next_seq = seq + 1
    tip.last_row_hash = content_hash
    await session.flush()  # surface FK/CHECK/unique violations before the caller commits

    return HuddleArchive(
        huddle_id=huddle_id,
        created_at=created_at,
        seq=seq,
        prev_record_hash=prev_hash,
        content_hash=content_hash,
    )
