"""Vector 10 — idempotency: a replayed idempotency key yields exactly one debit."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import ledger_entries


async def test_replayed_key_applies_once(tenant_db, tenant_id, make_balanced_txn):
    key = "evt-" + str(uuid.uuid4())

    first = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    async with tenant_db() as s:
        r1 = await append_transaction(s, first, idempotency_key=key)
    assert r1.applied is True

    # A DIFFERENT transaction id, same idempotency key — a replay.
    replay = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    async with tenant_db() as s:
        r2 = await append_transaction(s, replay, idempotency_key=key)
    assert r2.applied is False
    assert r2.idempotent_replay is True
    assert r2.entry_count == 0

    # Only the first transaction's entries exist (2, not 4).
    async with tenant_db() as s:
        count = (await s.execute(select(func.count()).select_from(ledger_entries))).scalar()
    assert count == 2


async def test_key_is_scoped_per_tenant(
    tenant_db, tenant_db_for, tenant_id, other_tenant_id, make_balanced_txn
):
    """The same key in two different tenants both apply (key is per-tenant)."""
    key = "shared-key"
    async with tenant_db() as s:
        await append_transaction(s, make_balanced_txn(tenant_id=tenant_id), idempotency_key=key)
    async with tenant_db_for(other_tenant_id) as s:
        r = await append_transaction(
            s, make_balanced_txn(tenant_id=other_tenant_id), idempotency_key=key
        )
    assert r.applied is True
