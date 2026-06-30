"""Vectors 11 & 12 — under concurrent appends the committed ledger never holds a
torn/unbalanced state and balances stay correct (no lost update).

Deterministic correctness test (Fork 6 — this runs in CI and must EXECUTE). The
heavy p95-latency benchmark is a separate local script, not asserted here.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from account_seed import ensure_accounts
from sqlalchemy import func, select

from delta.ledger import EntryDirection, LedgerEntry, Transaction
from delta.money import Money
from delta.persistence.balances import account_movement
from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import ledger_entries

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_N_WRITERS = 20
_CENTS = 100


def _txn(tenant_id, acct_x, acct_y):
    return Transaction(
        txn_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        entries=(
            LedgerEntry(
                entry_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                account_id=acct_x,
                direction=EntryDirection.DEBIT,
                amount=Money(minor_units=_CENTS, currency="USD"),
                team_id=str(uuid.uuid4()),
                project_id=str(uuid.uuid4()),
                agent_id="gateway-core",
                timestamp=_NOW,
            ),
            LedgerEntry(
                entry_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                account_id=acct_y,
                direction=EntryDirection.CREDIT,
                amount=Money(minor_units=_CENTS, currency="USD"),
                team_id=str(uuid.uuid4()),
                project_id=str(uuid.uuid4()),
                agent_id="gateway-core",
                timestamp=_NOW,
            ),
        ),
        timestamp=_NOW,
        description="concurrent",
    )


async def test_concurrent_writers_keep_ledger_balanced(tenant_db_for, tenant_id):
    acct_x = str(uuid.uuid4())
    acct_y = str(uuid.uuid4())

    # Seed the two custom accounts once (committed) so every concurrent writer's
    # entries satisfy the same-tenant FK.
    async with tenant_db_for(tenant_id) as s:
        await ensure_accounts(s, tenant_id, acct_x, acct_y)
        await s.commit()

    async def writer() -> None:
        async with tenant_db_for(tenant_id) as s:
            await append_transaction(s, _txn(tenant_id, acct_x, acct_y))

    await asyncio.gather(*(writer() for _ in range(_N_WRITERS)))

    async with tenant_db_for(tenant_id) as s:
        total = (await s.execute(select(func.count()).select_from(ledger_entries))).scalar()
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
        mv_x = await account_movement(s, acct_x)

    # Every writer committed both legs; the ledger balances; no lost update.
    assert total == 2 * _N_WRITERS
    assert int(debit) == int(credit) == _N_WRITERS * _CENTS
    assert mv_x.debit_minor_units == _N_WRITERS * _CENTS
