"""Reconciliation — vector 4 (allocation + entry-set consistency)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from delta.allocation import Allocation, AllocationTarget
from delta.budget import BudgetPeriod
from delta.ledger import EntryDirection
from delta.money import Money
from delta.reconciliation import reconcile_allocation, reconcile_entry_set

_TENANT = "22222222-2222-4222-8222-222222222222"


def test_reconcile_allocation_consistent():
    errs = reconcile_allocation(
        Money(minor_units=1000), [Money(minor_units=600), Money(minor_units=400)]
    )
    assert errs == []


def test_reconcile_allocation_flags_mismatch():
    # Vector 4: distributed 900 != total 1000.
    errs = reconcile_allocation(
        Money(minor_units=1000), [Money(minor_units=600), Money(minor_units=300)]
    )
    assert errs and "not reconciled" in errs[0]


def test_reconcile_allocation_flags_mixed_currency():
    errs = reconcile_allocation(
        Money(minor_units=1000, currency="USD"),
        [Money(minor_units=1000, currency="EUR")],
    )
    assert errs and "mixed-currency" in errs[0]


def test_allocation_consistent_by_construction():
    alloc = Allocation(
        allocation_id="33333333-3333-4333-8333-333333333333",
        tenant_id=_TENANT,
        total=Money(minor_units=1000),
        targets=[
            AllocationTarget(scope_ref="team-a", amount=Money(minor_units=700)),
            AllocationTarget(scope_ref="team-b", amount=Money(minor_units=300)),
        ],
        period=BudgetPeriod.MONTHLY,
    )
    assert alloc.total.minor_units == 1000


def test_allocation_rejects_inconsistent_total():
    # Vector 4: cannot construct an Allocation whose targets don't sum to total.
    with pytest.raises(ValidationError, match="not reconciled"):
        Allocation(
            allocation_id="44444444-4444-4444-8444-444444444444",
            tenant_id=_TENANT,
            total=Money(minor_units=1000),
            targets=[AllocationTarget(scope_ref="team-a", amount=Money(minor_units=999))],
            period=BudgetPeriod.MONTHLY,
        )


def test_reconcile_entry_set_consistent(make_entry):
    entries = [
        make_entry(tenant_id=_TENANT, direction=EntryDirection.DEBIT, cents=500),
        make_entry(tenant_id=_TENANT, direction=EntryDirection.CREDIT, cents=500),
    ]
    assert reconcile_entry_set(entries) == []


def test_reconcile_entry_set_flags_imbalance(make_entry):
    entries = [
        make_entry(tenant_id=_TENANT, direction=EntryDirection.DEBIT, cents=500),
        make_entry(tenant_id=_TENANT, direction=EntryDirection.CREDIT, cents=400),
    ]
    errs = reconcile_entry_set(entries)
    assert any("unbalanced" in e for e in errs)


def test_reconcile_entry_set_flags_cross_tenant(make_entry):
    entries = [
        make_entry(tenant_id=_TENANT, direction=EntryDirection.DEBIT, cents=500),
        make_entry(
            tenant_id="55555555-5555-4555-8555-555555555555",
            direction=EntryDirection.CREDIT,
            cents=500,
        ),
    ]
    errs = reconcile_entry_set(entries)
    assert any("cross-tenant" in e for e in errs)


def test_reconcile_entry_set_flags_mixed_currency(make_entry):
    entries = [
        make_entry(tenant_id=_TENANT, direction=EntryDirection.DEBIT, cents=500, currency="USD"),
        make_entry(tenant_id=_TENANT, direction=EntryDirection.CREDIT, cents=500, currency="EUR"),
    ]
    errs = reconcile_entry_set(entries)
    assert any("mixed-currency" in e for e in errs)


def test_reconcile_entry_set_empty():
    assert reconcile_entry_set([]) == ["empty entry set"]
