"""Ledger entries and the balanced-entry invariant (vectors 2, 7, 8).

A ``Transaction`` is the unit of double-entry: a frozen set of >= 2
``LedgerEntry`` rows. The ``@model_validator`` is the load-bearing integrity gate
and runs in the only construction path, and the type is frozen — so there is **no
code path that can produce or mutate an unbalanced, mixed-currency, or
cross-tenant transaction**. Balance is checked on exact integer cents.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .identifiers import AccountId, AgentId, EntryId, ProjectId, TeamId, TenantId, TransactionId
from .money import Money, require_aware_utc

_DESCRIPTION_MAX_LENGTH = 512
TransactionDescription = Annotated[str, StringConstraints(max_length=_DESCRIPTION_MAX_LENGTH)]


class EntryDirection(StrEnum):
    DEBIT = "debit"
    CREDIT = "credit"


class LedgerEntry(BaseModel):
    """One side of a transaction, attributed to the four Sentinel stable IDs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: EntryId
    tenant_id: TenantId
    account_id: AccountId
    direction: EntryDirection
    amount: Money
    team_id: TeamId
    project_id: ProjectId
    agent_id: AgentId
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "timestamp")


class Transaction(BaseModel):
    """A balanced set of ledger entries. Balanced by construction or rejected.

    ``entries`` is an immutable ``tuple`` (not a list), so the validated invariant
    cannot be undone by in-place mutation (no ``.append()``) — combined with
    ``frozen=True`` there is no normal mutation path back to an unbalanced /
    cross-tenant state. NOTE: ``model_construct()`` bypasses validation (a Pydantic
    escape hatch) and is NOT a supported construction path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    txn_id: TransactionId
    tenant_id: TenantId
    entries: tuple[LedgerEntry, ...] = Field(min_length=2, max_length=1024)
    timestamp: datetime
    description: TransactionDescription = ""

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "timestamp")

    @model_validator(mode="after")
    def _balanced(self) -> "Transaction":
        # Vector 8: one currency across the whole transaction (no silent cross-currency net).
        currencies = {entry.amount.currency for entry in self.entries}
        if len(currencies) != 1:
            raise ValueError(f"mixed-currency transaction rejected: {sorted(currencies)}")

        # Vector 7: every entry belongs to this transaction's tenant.
        for entry in self.entries:
            if entry.tenant_id != self.tenant_id:
                raise ValueError(
                    "cross-tenant entry rejected: entry tenant_id != transaction tenant_id"
                )

        # Vector 2: debits and credits net to zero (exact integer arithmetic).
        debit = sum(
            e.amount.minor_units for e in self.entries if e.direction is EntryDirection.DEBIT
        )
        credit = sum(
            e.amount.minor_units for e in self.entries if e.direction is EntryDirection.CREDIT
        )
        if debit != credit:
            raise ValueError(f"unbalanced transaction: debits {debit} != credits {credit}")
        return self
