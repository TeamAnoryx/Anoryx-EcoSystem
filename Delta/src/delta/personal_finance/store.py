"""Personal-finance persistence (D-021, ADR-0021).

Tenant-scoped reads/writes against ``personal_accounts``/``personal_transactions``/
``personal_budgets`` (migration 0014). Every function takes an already-open
:class:`AsyncSession` (from ``delta.persistence.database.get_tenant_session``) and
does NOT commit — the caller (``service.py``) owns the transaction, exactly like
``erp.store``/``crm.store``.

``personal_budgets`` is INSERT-only (mirrors D-018/D-019's "simplest possible write
pattern" precedent) — a budget change is a new row for that category+period, so
:func:`get_latest_budgets` reads the most recent row per category.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import personal_accounts, personal_budgets, personal_transactions

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class AccountRecord:
    account_id: str
    tenant_id: str
    type: str
    currency: str
    name: str
    created_at: datetime


@dataclass(frozen=True)
class TransactionRecord:
    txn_id: str
    tenant_id: str
    account_id: str
    category: str
    amount_minor_units: int
    currency: str
    description: str
    merchant: str | None
    occurred_at: datetime
    created_at: datetime
    source: str


@dataclass(frozen=True)
class BudgetRecord:
    budget_id: str
    tenant_id: str
    category: str
    cap_minor_units: int
    currency: str
    period: str
    created_at: datetime


def _account_from_row(row) -> AccountRecord:
    return AccountRecord(
        account_id=row.account_id,
        tenant_id=row.tenant_id,
        type=row.type,
        currency=row.currency,
        name=row.name,
        created_at=row.created_at,
    )


def _transaction_from_row(row) -> TransactionRecord:
    return TransactionRecord(
        txn_id=row.txn_id,
        tenant_id=row.tenant_id,
        account_id=row.account_id,
        category=row.category,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        description=row.description,
        merchant=row.merchant,
        occurred_at=row.occurred_at,
        created_at=row.created_at,
        source=row.source,
    )


def _budget_from_row(row) -> BudgetRecord:
    return BudgetRecord(
        budget_id=row.budget_id,
        tenant_id=row.tenant_id,
        category=row.category,
        cap_minor_units=row.cap_minor_units,
        currency=row.currency,
        period=row.period,
        created_at=row.created_at,
    )


async def create_account(
    session: AsyncSession,
    *,
    tenant_id: str,
    type: str,
    currency: str,
    name: str,
    now: datetime,
) -> AccountRecord:
    account_id = str(uuid.uuid4())
    await session.execute(
        insert(personal_accounts).values(
            account_id=account_id,
            tenant_id=tenant_id,
            type=type,
            currency=currency,
            name=name,
            created_at=now,
        )
    )
    return AccountRecord(
        account_id=account_id,
        tenant_id=tenant_id,
        type=type,
        currency=currency,
        name=name,
        created_at=now,
    )


async def list_accounts(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[AccountRecord]:
    stmt = (
        select(personal_accounts)
        .order_by(personal_accounts.c.created_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_account_from_row(r) for r in rows]


async def get_account(session: AsyncSession, *, account_id: str) -> AccountRecord | None:
    stmt = select(personal_accounts).where(personal_accounts.c.account_id == account_id)
    row = (await session.execute(stmt)).first()
    return _account_from_row(row) if row is not None else None


async def create_transaction(
    session: AsyncSession,
    *,
    tenant_id: str,
    account_id: str,
    category: str,
    amount_minor_units: int,
    currency: str,
    description: str,
    merchant: str | None,
    occurred_at: datetime,
    now: datetime,
    source: str = "manual",
) -> TransactionRecord:
    txn_id = str(uuid.uuid4())
    await session.execute(
        insert(personal_transactions).values(
            txn_id=txn_id,
            tenant_id=tenant_id,
            account_id=account_id,
            category=category,
            amount_minor_units=amount_minor_units,
            currency=currency,
            description=description,
            merchant=merchant,
            occurred_at=occurred_at,
            created_at=now,
            source=source,
        )
    )
    return TransactionRecord(
        txn_id=txn_id,
        tenant_id=tenant_id,
        account_id=account_id,
        category=category,
        amount_minor_units=amount_minor_units,
        currency=currency,
        description=description,
        merchant=merchant,
        occurred_at=occurred_at,
        created_at=now,
        source=source,
    )


async def list_transactions(
    session: AsyncSession,
    *,
    account_id: str | None = None,
    category: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[TransactionRecord]:
    stmt = select(personal_transactions)
    if account_id is not None:
        stmt = stmt.where(personal_transactions.c.account_id == account_id)
    if category is not None:
        stmt = stmt.where(personal_transactions.c.category == category)
    if start is not None:
        stmt = stmt.where(personal_transactions.c.occurred_at >= start)
    if end is not None:
        stmt = stmt.where(personal_transactions.c.occurred_at < end)
    stmt = stmt.order_by(personal_transactions.c.occurred_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_transaction_from_row(r) for r in rows]


async def create_budget(
    session: AsyncSession,
    *,
    tenant_id: str,
    category: str,
    cap_minor_units: int,
    currency: str,
    period: str,
    now: datetime,
) -> BudgetRecord:
    budget_id = str(uuid.uuid4())
    await session.execute(
        insert(personal_budgets).values(
            budget_id=budget_id,
            tenant_id=tenant_id,
            category=category,
            cap_minor_units=cap_minor_units,
            currency=currency,
            period=period,
            created_at=now,
        )
    )
    return BudgetRecord(
        budget_id=budget_id,
        tenant_id=tenant_id,
        category=category,
        cap_minor_units=cap_minor_units,
        currency=currency,
        period=period,
        created_at=now,
    )


async def get_latest_budgets(session: AsyncSession) -> list[BudgetRecord]:
    """One row per category: the most recently created budget (a category's current
    cap) — mirrors the "insert-only, read the latest" convention every budget change
    uses in this package (no UPDATE anywhere on ``personal_budgets``)."""
    latest_per_category = (
        select(
            personal_budgets.c.category,
            func.max(personal_budgets.c.created_at).label("latest_created_at"),
        )
        .group_by(personal_budgets.c.category)
        .subquery()
    )
    stmt = select(personal_budgets).join(
        latest_per_category,
        (personal_budgets.c.category == latest_per_category.c.category)
        & (personal_budgets.c.created_at == latest_per_category.c.latest_created_at),
    )
    rows = (await session.execute(stmt)).all()
    return [_budget_from_row(r) for r in rows]


@dataclass(frozen=True)
class CategorySpend:
    category: str
    spent_minor_units: int  # sum of abs(negative amounts) in the window


async def get_category_spend(
    session: AsyncSession, *, start: datetime, end: datetime, currency: str
) -> list[CategorySpend]:
    """Sum of expense (negative) amounts per category within ``[start, end)``,
    scoped to one reporting currency (D-001's no-FX rule)."""
    stmt = (
        select(
            personal_transactions.c.category,
            func.coalesce(func.sum(-personal_transactions.c.amount_minor_units), 0).label("spent"),
        )
        .where(
            personal_transactions.c.amount_minor_units < 0,
            personal_transactions.c.currency == currency,
            personal_transactions.c.occurred_at >= start,
            personal_transactions.c.occurred_at < end,
        )
        .group_by(personal_transactions.c.category)
    )
    rows = (await session.execute(stmt)).all()
    return [CategorySpend(category=r.category, spent_minor_units=int(r.spent)) for r in rows]


async def get_income_expense_totals(
    session: AsyncSession, *, start: datetime, end: datetime, currency: str
) -> tuple[int, int]:
    """(total_income_minor_units, total_expense_minor_units) within
    ``[start, end)``, scoped to one currency. Expense is returned as a positive
    magnitude (the caller's own sign convention — mirrors :func:`get_category_spend`)."""
    income_stmt = select(
        func.coalesce(func.sum(personal_transactions.c.amount_minor_units), 0)
    ).where(
        personal_transactions.c.amount_minor_units > 0,
        personal_transactions.c.currency == currency,
        personal_transactions.c.occurred_at >= start,
        personal_transactions.c.occurred_at < end,
    )
    expense_stmt = select(
        func.coalesce(func.sum(-personal_transactions.c.amount_minor_units), 0)
    ).where(
        personal_transactions.c.amount_minor_units < 0,
        personal_transactions.c.currency == currency,
        personal_transactions.c.occurred_at >= start,
        personal_transactions.c.occurred_at < end,
    )
    total_income = int((await session.execute(income_stmt)).scalar_one())
    total_expense = int((await session.execute(expense_stmt)).scalar_one())
    return total_income, total_expense
