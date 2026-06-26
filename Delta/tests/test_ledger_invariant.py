"""Double-entry invariant — vectors 2 (unbalanced), 7 (cross-tenant), 8 (currency-mix).

The invariant must be NON-BYPASSABLE: no construction or mutation path may yield an
unbalanced / mixed-currency / cross-tenant Transaction.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from delta.ledger import EntryDirection, Transaction
from delta.money import Money


def test_balanced_transaction_accepted(tenant_id, make_balanced_txn):
    txn = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    assert len(txn.entries) == 2


def test_unbalanced_transaction_rejected(tenant_id, make_entry):
    # Vector 2: debits (5000) != credits (4999).
    with pytest.raises(ValidationError, match="unbalanced"):
        Transaction(
            txn_id="00000000-0000-4000-8000-000000000001",
            tenant_id=tenant_id,
            entries=[
                make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=5000),
                make_entry(tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=4999),
            ],
            timestamp="2026-06-26T12:00:00Z",
        )


def test_single_entry_rejected(tenant_id, make_entry):
    with pytest.raises(ValidationError):
        Transaction(
            txn_id="00000000-0000-4000-8000-000000000002",
            tenant_id=tenant_id,
            entries=[make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=1)],
            timestamp="2026-06-26T12:00:00Z",
        )


def test_mixed_currency_rejected(tenant_id, make_entry):
    # Vector 8: equal numeric cents but different currencies must not net.
    with pytest.raises(ValidationError, match="mixed-currency"):
        Transaction(
            txn_id="00000000-0000-4000-8000-000000000003",
            tenant_id=tenant_id,
            entries=[
                make_entry(
                    tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=100, currency="USD"
                ),
                make_entry(
                    tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=100, currency="EUR"
                ),
            ],
            timestamp="2026-06-26T12:00:00Z",
        )


def test_cross_tenant_entry_rejected(tenant_id, make_entry):
    # Vector 7: an entry belonging to another tenant cannot ride inside this txn.
    other = "11111111-1111-4111-8111-111111111111"
    with pytest.raises(ValidationError, match="cross-tenant"):
        Transaction(
            txn_id="00000000-0000-4000-8000-000000000004",
            tenant_id=tenant_id,
            entries=[
                make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=100),
                make_entry(tenant_id=other, direction=EntryDirection.CREDIT, cents=100),
            ],
            timestamp="2026-06-26T12:00:00Z",
        )


def test_invariant_non_bypassable_frozen(tenant_id, make_balanced_txn):
    # Cannot mutate entries to smuggle in an imbalance after construction.
    txn = make_balanced_txn(tenant_id=tenant_id, cents=5000)
    # frozen blocks reassignment...
    with pytest.raises(ValidationError):
        txn.entries = ()  # type: ignore[misc]
    # ...and entries is an immutable tuple (H-1), so there is no in-place .append()
    # path to unbalance / cross-tenant a validated transaction.
    assert isinstance(txn.entries, tuple)
    with pytest.raises(AttributeError):
        txn.entries.append(txn.entries[0])  # type: ignore[attr-defined]


def test_multi_entry_balanced_accepted(tenant_id, make_entry):
    # 3000 + 2000 debit == 5000 credit.
    txn = Transaction(
        txn_id="00000000-0000-4000-8000-000000000005",
        tenant_id=tenant_id,
        entries=[
            make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=3000),
            make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=2000),
            make_entry(tenant_id=tenant_id, direction=EntryDirection.CREDIT, cents=5000),
        ],
        timestamp="2026-06-26T12:00:00Z",
    )
    assert len(txn.entries) == 3


def test_naive_timestamp_rejected(tenant_id, make_entry):
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_entry(
            tenant_id=tenant_id,
            direction=EntryDirection.DEBIT,
            cents=1,
            timestamp="2026-06-26T12:00:00",  # no offset
        )


def test_entry_amount_is_money(tenant_id, make_entry):
    e = make_entry(tenant_id=tenant_id, direction=EntryDirection.DEBIT, cents=7)
    assert isinstance(e.amount, Money)
    assert e.amount.minor_units == 7
