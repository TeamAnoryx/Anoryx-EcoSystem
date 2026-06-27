"""Vectors 1 & 2 — RLS tenant isolation: cross-tenant READ and WRITE are impossible
with delta_app (NOBYPASSRLS), and an unset/empty tenant context yields zero rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import ledger_entries, transactions

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


async def test_other_tenant_cannot_read(
    tenant_db, tenant_db_for, tenant_id, other_tenant_id, make_balanced_txn
):
    async with tenant_db() as s:
        await append_transaction(s, make_balanced_txn(tenant_id=tenant_id, cents=5000))

    # Tenant B sees nothing.
    async with tenant_db_for(other_tenant_id) as s:
        entries = (await s.execute(select(ledger_entries))).all()
        txns = (await s.execute(select(transactions))).all()
    assert entries == []
    assert txns == []

    # Tenant A sees its own.
    async with tenant_db() as s:
        count = (await s.execute(select(func.count()).select_from(ledger_entries))).scalar()
    assert count == 2


async def test_cross_tenant_write_rejected_by_with_check(tenant_db, tenant_id, other_tenant_id):
    """With GUC = A, inserting a row tagged tenant B violates the WITH CHECK policy."""
    async with tenant_db() as s:  # GUC = tenant_id (A)
        with pytest.raises(Exception) as excinfo:
            await s.execute(
                transactions.insert().values(
                    txn_id=str(uuid.uuid4()),
                    tenant_id=other_tenant_id,  # foreign tenant
                    currency="USD",
                    timestamp=_NOW,
                )
            )
            await s.commit()
    assert (
        "row-level security" in str(excinfo.value).lower() or "policy" in str(excinfo.value).lower()
    )


async def test_empty_guc_returns_zero_rows(tenant_db, tenant_db_for, tenant_id, make_balanced_txn):
    """The NULLIF predicate is unsatisfiable when the GUC is '' (fail-closed)."""
    async with tenant_db() as s:
        await append_transaction(s, make_balanced_txn(tenant_id=tenant_id, cents=5000))

    async with tenant_db_for("") as s:  # empty GUC
        rows = (await s.execute(select(ledger_entries.c.entry_id))).all()
    assert rows == []
