"""Balance + time-window read primitives (Fork 3): point-in-time, windowed, and
normal-balance signed balance. Pure derivation over the append-only entries.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from delta.ledger import EntryDirection, LedgerEntry, Transaction
from delta.money import Money
from delta.persistence.balances import account_balance, account_movement, windowed_movement
from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import accounts

_T1 = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_T2 = _T1 + timedelta(hours=1)


def _entry(tenant_id, account_id, direction, cents, ts):
    return LedgerEntry(
        entry_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        account_id=account_id,
        direction=direction,
        amount=Money(minor_units=cents, currency="USD"),
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
        timestamp=ts,
    )


async def _seed_two_txns(tenant_db, tenant_id, acct_x, acct_y):
    t1 = Transaction(
        txn_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        entries=(
            _entry(tenant_id, acct_x, EntryDirection.DEBIT, 5000, _T1),
            _entry(tenant_id, acct_y, EntryDirection.CREDIT, 5000, _T1),
        ),
        timestamp=_T1,
        description="t1",
    )
    t2 = Transaction(
        txn_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        entries=(
            _entry(tenant_id, acct_x, EntryDirection.DEBIT, 3000, _T2),
            _entry(tenant_id, acct_y, EntryDirection.CREDIT, 3000, _T2),
        ),
        timestamp=_T2,
        description="t2",
    )
    async with tenant_db() as s:
        await append_transaction(s, t1)
    async with tenant_db() as s:
        await append_transaction(s, t2)


async def _create_account(tenant_db, tenant_id, account_id, acct_type, name):
    async with tenant_db() as s:
        await s.execute(
            accounts.insert().values(
                account_id=account_id,
                tenant_id=tenant_id,
                type=acct_type,
                currency="USD",
                name=name,
            )
        )
        await s.commit()


async def test_full_history_movement(tenant_db, tenant_id):
    acct_x, acct_y = str(uuid.uuid4()), str(uuid.uuid4())
    await _seed_two_txns(tenant_db, tenant_id, acct_x, acct_y)
    async with tenant_db() as s:
        mv = await account_movement(s, acct_x)
    assert mv.debit_minor_units == 8000
    assert mv.credit_minor_units == 0


async def test_point_in_time_balance(tenant_db, tenant_id):
    acct_x, acct_y = str(uuid.uuid4()), str(uuid.uuid4())
    await _seed_two_txns(tenant_db, tenant_id, acct_x, acct_y)
    async with tenant_db() as s:
        mv = await account_movement(s, acct_x, as_of=_T1)  # only T1 (inclusive)
    assert mv.debit_minor_units == 5000


async def test_windowed_movement_half_open(tenant_db, tenant_id):
    acct_x, acct_y = str(uuid.uuid4()), str(uuid.uuid4())
    await _seed_two_txns(tenant_db, tenant_id, acct_x, acct_y)
    async with tenant_db() as s:
        mv = await windowed_movement(s, acct_x, start=_T1, end=_T1 + timedelta(minutes=30))
    assert mv.debit_minor_units == 5000  # T1 only; T2 falls outside [start, end)


async def test_normal_balance_signs(tenant_db, tenant_id):
    acct_x, acct_y = str(uuid.uuid4()), str(uuid.uuid4())
    await _create_account(tenant_db, tenant_id, acct_x, "asset", "Cash")
    await _create_account(tenant_db, tenant_id, acct_y, "revenue", "Sales")
    await _seed_two_txns(tenant_db, tenant_id, acct_x, acct_y)
    async with tenant_db() as s:
        bal_x = await account_balance(s, acct_x)  # asset: debit - credit
        bal_y = await account_balance(s, acct_y)  # revenue: credit - debit
    assert bal_x == 8000
    assert bal_y == 8000


async def test_unknown_account_raises(tenant_db, tenant_id):
    async with tenant_db() as s:
        with pytest.raises(LookupError):
            await account_balance(s, str(uuid.uuid4()))
