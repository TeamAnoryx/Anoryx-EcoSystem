"""Balance + time-window read primitives (D-003, Fork 3).

Balances are a PURE derivation — a ``SUM`` over the append-only entries on a single
MVCC snapshot — never a stored running-balance column. So a balance is always correct
under concurrency and can never desync from the ledger. These are the primitives the
budget engine (D-005) and the burn-rate dashboards (D-008) build on; D-003 ships the
read primitives only.

All queries run on a tenant-scoped session, so RLS confines every row to the caller's
tenant: a balance can only ever be computed over the caller's own ledger.

Existence semantics (intentional, not an oversight): ``account_movement`` and
``windowed_movement`` are type-agnostic raw aggregates — they sum whatever entries
carry an ``account_id`` and return ``Movement(0, 0)`` when there are none, so an
unknown account and a zero-movement account read alike. ``account_balance`` instead
needs the account's normal-balance ``type`` from ``delta.accounts`` and therefore
raises ``LookupError`` for an unknown account. D-003 does NOT FK ``ledger_entries``
to ``accounts``: Sentinel events carry no ``account_id`` (only the four stable IDs),
so the event→account posting mapping and the chart-of-accounts lifecycle belong to
the posting layer (D-004 ingest / D-005), which will own that referential integrity.
The ledger primitive accepts any well-formed ``account_id``.

Currency assumption: these primitives sum ``amount_minor_units`` with **no currency
dimension** — a balance is only meaningful for a single-currency account. D-001
gives each ``Account`` one ``currency``, and the posting layer is responsible for
only ever posting that currency to it (the DB deferred trigger already enforces one
currency per transaction *and* that entries match their transaction's currency). If
a future multi-currency account is introduced, these reads must gain a currency
filter; today they assume one currency per ``account_id``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..accounts import AccountType
from .models import accounts, ledger_entries

# Accounts whose balance increases on a DEBIT (assets, expenses). The rest
# (liability, equity, revenue) increase on a CREDIT.
_DEBIT_NORMAL = {AccountType.ASSET, AccountType.EXPENSE}


@dataclass(frozen=True)
class Movement:
    """Raw debit/credit totals over a set of entries (exact integer cents)."""

    debit_minor_units: int
    credit_minor_units: int

    @property
    def net_debit_minus_credit(self) -> int:
        return self.debit_minor_units - self.credit_minor_units


async def _movement(
    session: AsyncSession,
    account_id: str,
    *,
    as_of: datetime | None,
    start: datetime | None,
    end: datetime | None,
) -> Movement:
    debit = func.coalesce(
        func.sum(ledger_entries.c.amount_minor_units).filter(ledger_entries.c.direction == "debit"),
        0,
    )
    credit = func.coalesce(
        func.sum(ledger_entries.c.amount_minor_units).filter(
            ledger_entries.c.direction == "credit"
        ),
        0,
    )
    stmt = select(debit, credit).where(ledger_entries.c.account_id == account_id)
    if as_of is not None:
        stmt = stmt.where(ledger_entries.c.timestamp <= as_of)
    if start is not None:
        stmt = stmt.where(ledger_entries.c.timestamp >= start)
    if end is not None:
        stmt = stmt.where(ledger_entries.c.timestamp < end)  # half-open [start, end)

    row = (await session.execute(stmt)).one()
    return Movement(debit_minor_units=int(row[0]), credit_minor_units=int(row[1]))


async def account_movement(
    session: AsyncSession, account_id: str, *, as_of: datetime | None = None
) -> Movement:
    """Raw debit/credit totals for an account, optionally as-of a point in time.

    Type-agnostic: returns both totals so the caller can interpret them. ``as_of``
    (inclusive) gives a point-in-time view; omit it for the full history.
    """
    return await _movement(session, account_id, as_of=as_of, start=None, end=None)


async def windowed_movement(
    session: AsyncSession, account_id: str, *, start: datetime, end: datetime
) -> Movement:
    """Debit/credit totals over the half-open window ``[start, end)``.

    Matches the D-001 ``burn_rate`` window semantics; the burn-rate derivation source
    for D-008.
    """
    return await _movement(session, account_id, as_of=None, start=start, end=end)


async def account_balance(
    session: AsyncSession, account_id: str, *, as_of: datetime | None = None
) -> int:
    """Normal-balance signed balance of an account in integer minor units (cents).

    Asset/expense accounts increase on a debit (balance = debits − credits);
    liability/equity/revenue increase on a credit (balance = credits − debits). The
    account's ``type`` is read from ``delta.accounts`` (RLS-scoped). Raises if the
    account is unknown to this tenant.
    """
    type_row = (
        await session.execute(select(accounts.c.type).where(accounts.c.account_id == account_id))
    ).first()
    if type_row is None:
        raise LookupError(f"account {account_id} not found in this tenant's ledger")

    movement = await account_movement(session, account_id, as_of=as_of)
    if AccountType(type_row[0]) in _DEBIT_NORMAL:
        return movement.debit_minor_units - movement.credit_minor_units
    return movement.credit_minor_units - movement.debit_minor_units
