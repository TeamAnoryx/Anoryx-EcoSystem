"""Vector 5 — atomicity: a partial or orphaned write can never commit."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from delta.persistence.models import ledger_entries, transactions

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


async def test_orphan_entry_rejected(tenant_db, tenant_id):
    """An entry whose txn_id has no parent transaction is rejected.

    The BEFORE INSERT immutability trigger catches this first (parent xmin lookup is
    NULL → 'orphan' RAISE) before the FK constraint would; either rejection is
    correct — a partial/orphan write can never commit.
    """
    async with tenant_db() as s:
        with pytest.raises(Exception) as excinfo:
            await s.execute(
                ledger_entries.insert().values(
                    entry_id=str(uuid.uuid4()),
                    txn_id=str(uuid.uuid4()),  # no parent transaction
                    tenant_id=tenant_id,
                    account_id=str(uuid.uuid4()),
                    direction="debit",
                    amount_minor_units=100,
                    currency="USD",
                    team_id=str(uuid.uuid4()),
                    project_id=str(uuid.uuid4()),
                    agent_id="gateway-core",
                    timestamp=_NOW,
                )
            )
            await s.commit()
    msg = str(excinfo.value).lower()
    assert (
        "foreign key" in msg or "fk_entry_txn" in msg or "orphan" in msg or "does not exist" in msg
    )


async def test_failed_commit_persists_nothing(tenant_db, tenant_id, debit_account_id):
    """A rejected (unbalanced) write rolls back the txn row too — all-or-nothing."""
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
                account_id=debit_account_id,  # a real, seeded same-tenant account (FK)
                direction="debit",
                amount_minor_units=100,  # single leg → unbalanced
                currency="USD",
                team_id=str(uuid.uuid4()),
                project_id=str(uuid.uuid4()),
                agent_id="gateway-core",
                timestamp=_NOW,
            )
        )
        with pytest.raises(Exception, match="entries|unbalanced|double-entry"):
            await s.commit()

    # Nothing from the aborted transaction survived.
    async with tenant_db() as s:
        txn_count = (await s.execute(select(func.count()).select_from(transactions))).scalar()
        entry_count = (await s.execute(select(func.count()).select_from(ledger_entries))).scalar()
    assert txn_count == 0
    assert entry_count == 0
