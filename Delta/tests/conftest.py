"""Shared fixtures + non-stubbed factories for the D-001 suite.

No secrets, no PII in fixtures (random UUIDs only) — mirrors the Sentinel test
idiom and the secret-guard hook.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone

import pytest

from delta.ledger import EntryDirection, LedgerEntry, Transaction
from delta.money import Money

_FIXED_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def tenant_id() -> str:
    return new_uuid()


@pytest.fixture
def now() -> datetime:
    return _FIXED_NOW


@pytest.fixture
def make_entry() -> Callable[..., LedgerEntry]:
    """Factory: a valid LedgerEntry; override any field via kwargs."""

    def _make(
        *,
        tenant_id: str,
        direction: EntryDirection,
        cents: int,
        currency: str = "USD",
        timestamp: datetime | None = None,
        **over: object,
    ) -> LedgerEntry:
        fields: dict[str, object] = {
            "entry_id": new_uuid(),
            "tenant_id": tenant_id,
            "account_id": new_uuid(),
            "direction": direction,
            "amount": Money(minor_units=cents, currency=currency),
            "team_id": new_uuid(),
            "project_id": new_uuid(),
            "agent_id": "gateway-core",
            "timestamp": timestamp or _FIXED_NOW,
        }
        fields.update(over)
        return LedgerEntry(**fields)

    return _make


@pytest.fixture
def make_balanced_txn(make_entry: Callable[..., LedgerEntry]) -> Callable[..., Transaction]:
    """Factory: a balanced 2-entry transaction (one debit, one credit, equal cents)."""

    def _make(*, tenant_id: str, cents: int = 5000, currency: str = "USD") -> Transaction:
        return Transaction(
            txn_id=new_uuid(),
            tenant_id=tenant_id,
            entries=[
                make_entry(
                    tenant_id=tenant_id,
                    direction=EntryDirection.DEBIT,
                    cents=cents,
                    currency=currency,
                ),
                make_entry(
                    tenant_id=tenant_id,
                    direction=EntryDirection.CREDIT,
                    cents=cents,
                    currency=currency,
                ),
            ],
            timestamp=_FIXED_NOW,
            description="test transaction",
        )

    return _make
