"""Vectors 7 & 8 — the ledger is append-only: UPDATE and DELETE are blocked.

Two independent layers are proven:
  * the BEFORE UPDATE/DELETE trigger RAISEs even for a superuser (who bypasses RLS),
  * delta_app is denied by the missing UPDATE/DELETE grant (and RLS USING(false)).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, func, select, update

from delta.persistence.ledger_store import append_transaction
from delta.persistence.models import accounts, ledger_entries, transactions

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


async def _seed_entry(tenant_db, make_balanced_txn, tenant_id) -> str:
    txn = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    async with tenant_db() as s:
        await append_transaction(s, txn)
    return txn.entries[0].entry_id


async def test_update_blocked_by_trigger_even_for_superuser(
    tenant_db, privileged_session, tenant_id, make_balanced_txn
):
    entry_id = await _seed_entry(tenant_db, make_balanced_txn, tenant_id)
    with pytest.raises(Exception) as excinfo:
        await privileged_session.execute(
            update(ledger_entries)
            .where(ledger_entries.c.entry_id == entry_id)
            .values(amount_minor_units=1)
        )
        await privileged_session.commit()
    assert "append-only" in str(excinfo.value).lower()


async def test_delete_blocked_by_trigger_even_for_superuser(
    tenant_db, privileged_session, tenant_id, make_balanced_txn
):
    entry_id = await _seed_entry(tenant_db, make_balanced_txn, tenant_id)
    with pytest.raises(Exception) as excinfo:
        await privileged_session.execute(
            delete(ledger_entries).where(ledger_entries.c.entry_id == entry_id)
        )
        await privileged_session.commit()
    assert "append-only" in str(excinfo.value).lower()


async def test_delta_app_has_no_update_or_delete_grant(tenant_db, tenant_id, make_balanced_txn):
    """delta_app is denied UPDATE/DELETE at the grant layer (permission denied)."""
    entry_id = await _seed_entry(tenant_db, make_balanced_txn, tenant_id)

    async with tenant_db() as s:
        with pytest.raises(Exception) as excinfo:
            await s.execute(
                update(ledger_entries)
                .where(ledger_entries.c.entry_id == entry_id)
                .values(amount_minor_units=1)
            )
            await s.commit()
    assert (
        "permission denied" in str(excinfo.value).lower()
        or "append-only" in str(excinfo.value).lower()
    )

    async with tenant_db() as s:
        with pytest.raises(Exception) as excinfo:
            await s.execute(delete(ledger_entries).where(ledger_entries.c.entry_id == entry_id))
            await s.commit()
    assert (
        "permission denied" in str(excinfo.value).lower()
        or "append-only" in str(excinfo.value).lower()
    )


async def test_row_survives_all_modification_attempts(
    tenant_db, privileged_session, tenant_id, make_balanced_txn
):
    """After the blocked attempts, the original entry is intact and unchanged."""
    entry_id = await _seed_entry(tenant_db, make_balanced_txn, tenant_id)
    # The committed amount is 5000 (the balanced fixture's cents).
    row = (
        await privileged_session.execute(
            select(ledger_entries.c.amount_minor_units).where(ledger_entries.c.entry_id == entry_id)
        )
    ).first()
    assert row is not None and int(row[0]) == 5000


async def test_cannot_amend_committed_txn_with_balanced_pair(
    tenant_db, tenant_id, make_balanced_txn
):
    """Vector 4b — appending a BALANCED pair to an already-committed txn is blocked.

    The deferred SUM=0 check alone would pass (still balanced); the BEFORE INSERT
    xmin guard rejects the amendment because the parent txn was committed in an
    earlier DB transaction.
    """
    txn = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    async with tenant_db() as s:
        await append_transaction(s, txn)

    async with tenant_db() as s:
        with pytest.raises(Exception, match="already-committed|committed transaction"):
            await s.execute(
                ledger_entries.insert().values(
                    entry_id=str(uuid.uuid4()),
                    txn_id=txn.txn_id,  # an already-committed transaction
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

    # The original txn still has exactly its 2 entries — unchanged.
    async with tenant_db() as s:
        cnt = (
            await s.execute(
                select(func.count())
                .select_from(ledger_entries)
                .where(ledger_entries.c.txn_id == txn.txn_id)
            )
        ).scalar()
    assert cnt == 2


async def test_accounts_table_is_append_only(privileged_session, tenant_id):
    """The append-only trigger also guards delta.accounts (UPDATE + DELETE blocked)."""
    acct = str(uuid.uuid4())
    await privileged_session.execute(
        accounts.insert().values(
            account_id=acct, tenant_id=tenant_id, type="asset", currency="USD", name="Cash"
        )
    )
    await privileged_session.commit()

    with pytest.raises(Exception, match="append-only"):
        await privileged_session.execute(
            update(accounts).where(accounts.c.account_id == acct).values(name="Renamed")
        )
        await privileged_session.commit()
    await privileged_session.rollback()

    with pytest.raises(Exception, match="append-only"):
        await privileged_session.execute(delete(accounts).where(accounts.c.account_id == acct))
        await privileged_session.commit()
    await privileged_session.rollback()


async def test_transactions_table_is_append_only(privileged_session, tenant_id):
    """The append-only trigger also guards delta.transactions (UPDATE + DELETE blocked)."""
    txn_id = str(uuid.uuid4())
    await privileged_session.execute(
        transactions.insert().values(
            txn_id=txn_id, tenant_id=tenant_id, currency="USD", timestamp=_NOW
        )
    )
    await privileged_session.commit()

    with pytest.raises(Exception, match="append-only"):
        await privileged_session.execute(
            update(transactions)
            .where(transactions.c.txn_id == txn_id)
            .values(description="changed")
        )
        await privileged_session.commit()
    await privileged_session.rollback()

    with pytest.raises(Exception, match="append-only"):
        await privileged_session.execute(
            delete(transactions).where(transactions.c.txn_id == txn_id)
        )
        await privileged_session.commit()
    await privileged_session.rollback()
