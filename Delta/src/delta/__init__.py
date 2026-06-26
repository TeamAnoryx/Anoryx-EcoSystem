"""Delta financial domain model (D-001).

Canonical financial vocabulary + integrity invariants only. No ledger engine
(D-003), no budget engine (D-005), no DDL. See docs/adr/0001.
"""

from __future__ import annotations

from .accounts import Account, AccountType
from .allocation import Allocation, AllocationTarget
from .attribution import Attribution, budget_concept_to_policy_payload
from .budget import BudgetConcept, BudgetPeriod, BudgetScope
from .burn_rate import BurnRate, burn_rate
from .cost_center import CostCenter, Project
from .ledger import EntryDirection, LedgerEntry, Transaction
from .money import (
    DEFAULT_CURRENCY,
    MAX_BUDGET_COST_CENTS,
    MAX_BUDGET_TOKENS,
    MAX_MONEY_MINOR_UNITS,
    MAX_USAGE_COST_CENTS,
    MAX_USAGE_TOKENS,
    Money,
)
from .reconciliation import reconcile_allocation, reconcile_entry_set
from .usage import TimeWindow, UsageRecord, WindowGranularity

__all__ = [
    "Account",
    "AccountType",
    "Allocation",
    "AllocationTarget",
    "Attribution",
    "budget_concept_to_policy_payload",
    "BudgetConcept",
    "BudgetPeriod",
    "BudgetScope",
    "BurnRate",
    "burn_rate",
    "CostCenter",
    "Project",
    "EntryDirection",
    "LedgerEntry",
    "Transaction",
    "Money",
    "DEFAULT_CURRENCY",
    "MAX_BUDGET_COST_CENTS",
    "MAX_BUDGET_TOKENS",
    "MAX_MONEY_MINOR_UNITS",
    "MAX_USAGE_COST_CENTS",
    "MAX_USAGE_TOKENS",
    "reconcile_allocation",
    "reconcile_entry_set",
    "TimeWindow",
    "UsageRecord",
    "WindowGranularity",
]
