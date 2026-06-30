"""Vector 9 — reversal correctness: a reversal is a NEW balanced compensating
transaction; the original is untouched and the ledger remains balanced.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from account_seed import ensure_accounts
from sqlalchemy import func, select

from delta.ledger import EntryDirection, LedgerEntry, Transaction
from delta.money import Money
from delta.persistence.balances import account_movement
from delta.persistence.ledger_store import append_transaction, reverse_transaction
from delta.persistence.models import ledger_entries, transactions

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def _entry(tenant_id, account_id, direction, cents):
    return LedgerEntry(
        entry_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        account_id=account_id,
        direction=direction,
        amount=Money(minor_units=cents, currency="USD"),
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
        timestamp=_NOW,
    )


async def test_reversal_balances_and_leaves_original(tenant_db, tenant_id):
    acct_x = str(uuid.uuid4())
    acct_y = str(uuid.uuid4())
    original = Transaction(
        txn_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        entries=(
            _entry(tenant_id, acct_x, EntryDirection.DEBIT, 5000),
            _entry(tenant_id, acct_y, EntryDirection.CREDIT, 5000),
        ),
        timestamp=_NOW,
        description="original",
    )
    async with tenant_db() as s:
        await ensure_accounts(s, tenant_id, acct_x, acct_y)
        await append_transaction(s, original)

    rev_id = str(uuid.uuid4())
    async with tenant_db() as s:
        result = await reverse_transaction(s, original.txn_id, new_txn_id=rev_id, timestamp=_NOW)
    assert result.applied and result.entry_count == 2

    async with tenant_db() as s:
        # Original entries still present and unchanged (2 rows for the original txn).
        orig_rows = (
            await s.execute(
                select(ledger_entries).where(ledger_entries.c.txn_id == original.txn_id)
            )
        ).all()
        assert len(orig_rows) == 2

        # The reversal links back to the original.
        rev = (
            await s.execute(
                select(transactions.c.reversal_of).where(transactions.c.txn_id == rev_id)
            )
        ).first()
        assert rev is not None and rev[0] == original.txn_id

        # Each account nets to zero after the compensating transaction.
        mv_x = await account_movement(s, acct_x)
        mv_y = await account_movement(s, acct_y)
    assert mv_x.net_debit_minus_credit == 0
    assert mv_y.net_debit_minus_credit == 0


async def test_ledger_balanced_after_reversal(tenant_db, tenant_id, make_balanced_txn):
    txn = make_balanced_txn(tenant_id=tenant_id, cents=4200)
    async with tenant_db() as s:
        await append_transaction(s, txn)
    async with tenant_db() as s:
        await reverse_transaction(s, txn.txn_id, new_txn_id=str(uuid.uuid4()), timestamp=_NOW)

    # Total debits == total credits across the whole tenant ledger.
    async with tenant_db() as s:
        debit = (
            await s.execute(
                select(func.coalesce(func.sum(ledger_entries.c.amount_minor_units), 0)).where(
                    ledger_entries.c.direction == "debit"
                )
            )
        ).scalar()
        credit = (
            await s.execute(
                select(func.coalesce(func.sum(ledger_entries.c.amount_minor_units), 0)).where(
                    ledger_entries.c.direction == "credit"
                )
            )
        ).scalar()
    assert int(debit) == int(credit)


async def test_reverse_unknown_transaction_raises(tenant_db, tenant_id):
    """Reversing a transaction not in this tenant's ledger raises TransactionNotFoundError."""
    import pytest

    from delta.persistence.ledger_store import TransactionNotFoundError

    async with tenant_db() as s:
        with pytest.raises(TransactionNotFoundError):
            await reverse_transaction(
                s, str(uuid.uuid4()), new_txn_id=str(uuid.uuid4()), timestamp=_NOW
            )
