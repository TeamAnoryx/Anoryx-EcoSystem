"""Reconciliation rules as callable checks (vector 4).

These operate on raw components (not pre-validated aggregates) so they can be fed
an inconsistent set and *flag* it — the complement to the hard invariants on
``Transaction`` / ``Allocation`` which *reject* inconsistency at construction.
Each function returns a list of human-readable error strings; an empty list means
consistent (mirroring the ``schema_validator`` idiom).
"""

from __future__ import annotations

from collections.abc import Sequence

from .ledger import EntryDirection, LedgerEntry
from .money import Money


def reconcile_allocation(total: Money, targets: Sequence[Money]) -> list[str]:
    """An allocation is reconciled iff its targets share its currency and sum to its total."""
    errors: list[str] = []
    currencies = {total.currency} | {t.currency for t in targets}
    if len(currencies) != 1:
        errors.append(f"mixed-currency allocation rejected: {sorted(currencies)}")
        return errors  # a cross-currency sum is meaningless; stop here
    distributed = sum(t.minor_units for t in targets)
    if distributed != total.minor_units:
        errors.append(
            f"allocation not reconciled: distributed {distributed} != total {total.minor_units}"
        )
    return errors


def reconcile_entry_set(entries: Sequence[LedgerEntry]) -> list[str]:
    """A ledger entry set is consistent iff one tenant, one currency, debits == credits."""
    errors: list[str] = []
    if not entries:
        return ["empty entry set"]
    currencies = {e.amount.currency for e in entries}
    if len(currencies) != 1:
        errors.append(f"mixed-currency entry set: {sorted(currencies)}")
    tenants = {e.tenant_id for e in entries}
    if len(tenants) != 1:
        errors.append(f"cross-tenant entry set: {len(tenants)} distinct tenant_id values")
    debit = sum(e.amount.minor_units for e in entries if e.direction is EntryDirection.DEBIT)
    credit = sum(e.amount.minor_units for e in entries if e.direction is EntryDirection.CREDIT)
    if debit != credit:
        errors.append(f"unbalanced entry set: debits {debit} != credits {credit}")
    return errors
