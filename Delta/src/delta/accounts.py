"""Accounts — the double-entry chart-of-accounts node.

An ``Account`` is tenant-scoped (``tenant_id`` first) and carries a normal-balance
``type``. Posting/normal-balance *enforcement* is the ledger engine's job (D-003);
here the type is vocabulary.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from .identifiers import AccountId, TenantId
from .money import Currency

_NAME_MAX_LENGTH = 256
AccountName = Annotated[str, StringConstraints(min_length=1, max_length=_NAME_MAX_LENGTH)]


class AccountType(StrEnum):
    """The five classical account types."""

    ASSET = "asset"
    LIABILITY = "liability"
    EQUITY = "equity"
    REVENUE = "revenue"
    EXPENSE = "expense"


class Account(BaseModel):
    """A tenant-scoped chart-of-accounts node."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    account_id: AccountId
    tenant_id: TenantId
    type: AccountType
    currency: Currency
    name: AccountName
