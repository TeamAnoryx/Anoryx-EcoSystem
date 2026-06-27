"""The atomic ledger write path: append, reverse, idempotent dedup (D-003).

Every write goes through here, but correctness does NOT depend on it: the database
enforces the balanced invariant (deferred constraint trigger), append-only
(triggers + grants + RLS), tenant isolation (RLS), and idempotency (unique index).
This module is the convenient, validated front door — a bug here cannot commit an
unbalanced, mutated, cross-tenant, or duplicated state, because the DB rejects it.

Sessions are the tenant-scoped sessions from ``database.get_tenant_session`` (already
in a transaction — autobegun). Callers commit via these functions; on the balanced
trigger's COMMIT-time rejection the commit raises and nothing is persisted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..ledger import EntryDirection, LedgerEntry, Transaction
from ..money import Money
from .models import ledger_entries, transactions

_OPPOSITE = {
    EntryDirection.DEBIT: EntryDirection.CREDIT,
    EntryDirection.CREDIT: EntryDirection.DEBIT,
}


class LedgerError(RuntimeError):
    """A ledger write violated an invariant the DB or store rejected."""


class TransactionNotFoundError(LedgerError):
    """The transaction to reverse does not exist in this tenant's ledger."""


@dataclass(frozen=True)
class AppendResult:
    """Outcome of an append. ``applied`` is False only on an idempotent replay.

    NOTE on ``txn_id`` for an idempotent replay (``idempotent_replay=True``): it is
    the caller-supplied replay transaction id, for which NO entries were written.
    The canonical first-writer transaction (the one that holds the entries) shares
    the same ``(tenant_id, idempotency_key)``; query by that key to find it.
    """

    txn_id: str
    applied: bool
    idempotent_replay: bool
    entry_count: int


def _txn_currency(txn: Transaction) -> str:
    # The D-001 Transaction validator guarantees one currency across all entries.
    return txn.entries[0].amount.currency


async def append_transaction(
    session: AsyncSession,
    txn: Transaction,
    *,
    idempotency_key: str | None = None,
    reversal_of: str | None = None,
) -> AppendResult:
    """Append one balanced transaction (its txn row + all entries) atomically.

    The ``txn`` is a D-001 ``Transaction`` — already validated balanced, single
    currency, single tenant in Pydantic (an early, legible guard). The DEFERRED
    balanced-constraint trigger is the authority: it re-checks the full entry set at
    COMMIT, so a partial or unbalanced write can never commit.

    Idempotency (Fork 5): when ``idempotency_key`` is given, the txn row is inserted
    with ``ON CONFLICT (tenant_id, idempotency_key) DO NOTHING``. A replay that
    conflicts inserts nothing and inserts NO entries — exactly one debit survives a
    replay. The conflict waits on the concurrent inserter, so a race resolves to one
    winner.
    """
    txn_values = {
        "txn_id": txn.txn_id,
        "tenant_id": txn.tenant_id,
        "currency": _txn_currency(txn),
        "timestamp": txn.timestamp,
        "description": txn.description,
        "reversal_of": reversal_of,
        "idempotency_key": idempotency_key,
    }

    stmt = pg_insert(transactions).values(**txn_values)
    if idempotency_key is not None:
        # Must match the PARTIAL unique index ux_txn_idempotency — its predicate
        # (idempotency_key IS NOT NULL) has to be named for ON CONFLICT to bind it.
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["tenant_id", "idempotency_key"],
            index_where=text("idempotency_key IS NOT NULL"),
        )
    stmt = stmt.returning(transactions.c.txn_id)

    inserted = (await session.execute(stmt)).first()
    if idempotency_key is not None and inserted is None:
        # Idempotent replay: the (tenant, key) row already exists. Insert no entries;
        # commit to release the autobegun transaction cleanly.
        await session.commit()
        return AppendResult(txn_id=txn.txn_id, applied=False, idempotent_replay=True, entry_count=0)

    await session.execute(
        ledger_entries.insert(),
        [
            {
                "entry_id": e.entry_id,
                "txn_id": txn.txn_id,
                "tenant_id": e.tenant_id,
                "account_id": e.account_id,
                "direction": e.direction.value,
                "amount_minor_units": e.amount.minor_units,
                "currency": e.amount.currency,
                "team_id": e.team_id,
                "project_id": e.project_id,
                "agent_id": e.agent_id,
                "timestamp": e.timestamp,
            }
            for e in txn.entries
        ],
    )
    # COMMIT fires the DEFERRED balanced trigger; an imbalance raises here.
    await session.commit()
    return AppendResult(
        txn_id=txn.txn_id,
        applied=True,
        idempotent_replay=False,
        entry_count=len(txn.entries),
    )


async def reverse_transaction(
    session: AsyncSession,
    original_txn_id: str,
    *,
    new_txn_id: str,
    timestamp: datetime,
    description: str = "",
    idempotency_key: str | None = None,
) -> AppendResult:
    """Reverse a transaction as a NEW compensating balanced transaction.

    Reversal is never a mutation. We read the original entries (RLS-scoped to the
    caller's tenant), swap debit<->credit for the same amounts/accounts, and append a
    new transaction whose ``reversal_of`` points at the original. Swapping the
    directions of a balanced set yields a balanced set, so the compensating txn is
    balanced by construction (and re-validated by the deferred trigger). The original
    transaction and its entries are left exactly as written.
    """
    rows = (
        await session.execute(
            select(ledger_entries).where(ledger_entries.c.txn_id == original_txn_id)
        )
    ).all()
    if not rows:
        # Either it does not exist or RLS hides it (other tenant) — same outcome.
        raise TransactionNotFoundError(
            f"transaction {original_txn_id} not found in this tenant's ledger"
        )

    compensating_entries = [
        LedgerEntry(
            entry_id=str(uuid.uuid4()),
            tenant_id=r.tenant_id,
            account_id=r.account_id,
            direction=_OPPOSITE[EntryDirection(r.direction)],
            amount=Money(minor_units=r.amount_minor_units, currency=r.currency),
            team_id=r.team_id,
            project_id=r.project_id,
            agent_id=r.agent_id,
            timestamp=timestamp,
        )
        for r in rows
    ]
    compensating = Transaction(
        txn_id=new_txn_id,
        tenant_id=rows[0].tenant_id,
        entries=tuple(compensating_entries),
        timestamp=timestamp,
        description=description or f"reversal of {original_txn_id}",
    )
    return await append_transaction(
        session,
        compensating,
        idempotency_key=idempotency_key,
        reversal_of=original_txn_id,
    )
