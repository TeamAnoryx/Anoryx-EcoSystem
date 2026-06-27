"""Vectors 4 & 6 — the balanced invariant is enforced by the DATABASE, not the app.

These are non-stubbed tests on a real Postgres. The deferred constraint trigger must
reject any transaction whose entries do not net to zero AT COMMIT — even one written
by a raw SQL INSERT that never touches the store.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from delta.ledger import EntryDirection, Transaction
from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import ledger_entries, transactions

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


async def test_balanced_transaction_commits(tenant_db, tenant_id, make_balanced_txn):
    txn = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    async with tenant_db() as s:
        result = await append_transaction(s, txn)
    assert result.applied is True
    assert result.entry_count == 2

    async with tenant_db() as s:
        rows = (
            await s.execute(select(ledger_entries).where(ledger_entries.c.txn_id == txn.txn_id))
        ).all()
    assert len(rows) == 2


async def test_single_unbalanced_insert_rejected_at_commit(tenant_db, tenant_id):
    """A direct single-leg INSERT (count < 2) must be REJECTED at COMMIT."""
    txn_id = str(uuid.uuid4())
    async with tenant_db() as s:
        await s.execute(
            transactions.insert().values(
                txn_id=txn_id, tenant_id=tenant_id, currency="USD", timestamp=_NOW
            )
        )
        await s.execute(
            ledger_entries.insert().values(
                entry_id=str(uuid.uuid4()),
                txn_id=txn_id,
                tenant_id=tenant_id,
                account_id=str(uuid.uuid4()),
                direction="debit",
                amount_minor_units=5000,
                currency="USD",
                team_id=str(uuid.uuid4()),
                project_id=str(uuid.uuid4()),
                agent_id="gateway-core",
                timestamp=_NOW,
            )
        )
        with pytest.raises(Exception) as excinfo:
            await s.commit()
    msg = str(excinfo.value).lower()
    assert "entries" in msg or "unbalanced" in msg or "double-entry" in msg


async def test_unbalanced_two_entry_txn_rejected(tenant_db, tenant_id, make_entry):
    """Two entries that do not net to zero must be REJECTED at COMMIT."""
    debit = make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=5000)
    credit = make_entry(tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=4000)
    txn_id = str(uuid.uuid4())
    async with tenant_db() as s:
        await s.execute(
            transactions.insert().values(
                txn_id=txn_id, tenant_id=tenant_id, currency="USD", timestamp=_NOW
            )
        )
        for e in (debit, credit):
            await s.execute(
                ledger_entries.insert().values(
                    entry_id=e.entry_id,
                    txn_id=txn_id,
                    tenant_id=e.tenant_id,
                    account_id=e.account_id,
                    direction=e.direction.value,
                    amount_minor_units=e.amount.minor_units,
                    currency=e.amount.currency,
                    team_id=e.team_id,
                    project_id=e.project_id,
                    agent_id=e.agent_id,
                    timestamp=e.timestamp,
                )
            )
        with pytest.raises(Exception) as excinfo:
            await s.commit()
    assert "debits" in str(excinfo.value).lower() or "unbalanced" in str(excinfo.value).lower()


async def test_balanced_multi_entry_txn_commits(tenant_db, tenant_id, make_entry):
    """A 3-leg balanced transaction (split) commits."""
    entries = (
        make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=7000),
        make_entry(tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=3000),
        make_entry(tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=4000),
    )
    txn = Transaction(
        txn_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        entries=entries,
        timestamp=_NOW,
        description="split",
    )
    async with tenant_db() as s:
        result = await append_transaction(s, txn)
    assert result.applied and result.entry_count == 3


async def test_entry_currency_must_match_txn_currency(tenant_db, tenant_id, make_entry):
    """L-2 guard: balanced USD entries under a txn row tagged EUR are REJECTED at COMMIT."""
    debit = make_entry(
        tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=5000, currency="USD"
    )
    credit = make_entry(
        tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=5000, currency="USD"
    )
    txn_id = str(uuid.uuid4())
    async with tenant_db() as s:
        await s.execute(
            transactions.insert().values(
                txn_id=txn_id, tenant_id=tenant_id, currency="EUR", timestamp=_NOW
            )
        )
        for e in (debit, credit):
            await s.execute(
                ledger_entries.insert().values(
                    entry_id=e.entry_id,
                    txn_id=txn_id,
                    tenant_id=e.tenant_id,
                    account_id=e.account_id,
                    direction=e.direction.value,
                    amount_minor_units=e.amount.minor_units,
                    currency=e.amount.currency,
                    team_id=e.team_id,
                    project_id=e.project_id,
                    agent_id=e.agent_id,
                    timestamp=e.timestamp,
                )
            )
        with pytest.raises(Exception, match="currency"):
            await s.commit()
