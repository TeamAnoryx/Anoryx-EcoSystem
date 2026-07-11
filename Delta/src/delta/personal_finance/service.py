"""Personal-finance orchestration (D-021, ADR-0021).

``get_financial_health`` composes two independently-computed signals into a single
0-100 score:

- **Savings points (0-60)**: derived from the window's savings rate
  ``(income - expense) / income``, clamped to ``[-1, 1]`` and linearly mapped to
  ``[0, 60]``. If NO income was recorded in the window, this contributes exactly
  ``0`` — never silently skipped/reweighted (mirrors D-011's ``insufficient_data``
  honesty convention: a missing signal is scored as absent, not assumed favorable).
- **Budget-adherence points (0-40)**: the fraction of the tenant's currently-defined
  budget categories whose spend in the window is within cap, scaled to ``[0, 40]``.
  If NO budgets are defined, this contributes exactly ``0`` (same honesty rule).

This is a DETERMINISTIC arithmetic heuristic, not machine learning or AI — mirrors
D-011's "predictive" forecasting (current-rate projection) and D-015's "AI-driven"
bottleneck detection (a fixed heuristic), both plain arithmetic under an AI-sounding
roadmap name. See ADR-0021 §2 for the disclosed formula and its honesty boundary.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from . import store
from .schemas import (
    AccountCreateRequest,
    AccountView,
    BudgetCreateRequest,
    BudgetStatusView,
    BudgetView,
    FinancialHealthQuery,
    FinancialHealthView,
    TransactionCreateRequest,
    TransactionView,
)

_SAVINGS_MAX_POINTS = 60
_BUDGET_MAX_POINTS = 40


def _account_view(record: store.AccountRecord) -> AccountView:
    return AccountView(
        account_id=record.account_id,
        tenant_id=record.tenant_id,
        type=record.type,
        currency=record.currency,
        name=record.name,
        created_at=record.created_at,
    )


def _transaction_view(record: store.TransactionRecord) -> TransactionView:
    return TransactionView(
        txn_id=record.txn_id,
        tenant_id=record.tenant_id,
        account_id=record.account_id,
        category=record.category,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,
        description=record.description,
        merchant=record.merchant,
        occurred_at=record.occurred_at,
        created_at=record.created_at,
        source=record.source,
    )


def _budget_view(record: store.BudgetRecord) -> BudgetView:
    return BudgetView(
        budget_id=record.budget_id,
        tenant_id=record.tenant_id,
        category=record.category,
        cap_minor_units=record.cap_minor_units,
        currency=record.currency,
        period=record.period,
        created_at=record.created_at,
    )


async def create_account(
    session: AsyncSession, req: AccountCreateRequest, *, now: datetime
) -> AccountView:
    record = await store.create_account(
        session,
        tenant_id=req.tenant_id,
        type=req.type,
        currency=req.currency,
        name=req.name,
        now=now,
    )
    await session.commit()
    return _account_view(record)


async def list_accounts(session: AsyncSession, *, limit: int) -> list[AccountView]:
    records = await store.list_accounts(session, limit=limit)
    return [_account_view(r) for r in records]


class AccountNotFoundError(Exception):
    pass


async def create_transaction(
    session: AsyncSession, req: TransactionCreateRequest, *, now: datetime
) -> TransactionView:
    account = await store.get_account(session, account_id=req.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        raise AccountNotFoundError(req.account_id)
    record = await store.create_transaction(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        category=req.category,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        description=req.description,
        merchant=req.merchant,
        occurred_at=req.occurred_at,
        now=now,
    )
    await session.commit()
    return _transaction_view(record)


async def list_transactions(
    session: AsyncSession,
    *,
    account_id: str | None,
    category: str | None,
    start: datetime | None,
    end: datetime | None,
    limit: int,
) -> list[TransactionView]:
    records = await store.list_transactions(
        session, account_id=account_id, category=category, start=start, end=end, limit=limit
    )
    return [_transaction_view(r) for r in records]


async def create_budget(
    session: AsyncSession, req: BudgetCreateRequest, *, now: datetime
) -> BudgetView:
    record = await store.create_budget(
        session,
        tenant_id=req.tenant_id,
        category=req.category,
        cap_minor_units=req.cap_minor_units,
        currency=req.currency,
        period=req.period,
        now=now,
    )
    await session.commit()
    return _budget_view(record)


async def list_budgets(session: AsyncSession) -> list[BudgetView]:
    records = await store.get_latest_budgets(session)
    return [_budget_view(r) for r in records]


def _savings_points(total_income: int, total_expense: int) -> int:
    if total_income <= 0:
        return 0
    savings_rate = (total_income - total_expense) / total_income
    savings_rate = max(-1.0, min(1.0, savings_rate))
    return round((savings_rate + 1.0) / 2.0 * _SAVINGS_MAX_POINTS)


def _budget_points(budgets_within_cap: int, budget_count: int) -> int:
    if budget_count <= 0:
        return 0
    return round(budgets_within_cap / budget_count * _BUDGET_MAX_POINTS)


async def get_financial_health(
    session: AsyncSession, query: FinancialHealthQuery, *, now: datetime, currency: str
) -> FinancialHealthView:
    total_income, total_expense = await store.get_income_expense_totals(
        session, start=query.start, end=query.end, currency=currency
    )
    savings_rate = (total_income - total_expense) / total_income if total_income > 0 else None

    # Currency-scoped: a budget capped in a different currency than this report's
    # spend figures is EXCLUDED from the adherence calculation, never silently scored
    # as within-cap against a spend of 0 (security audit finding, ADR-0021 §2 Fork 9).
    latest_budgets = await store.get_latest_budgets(session, currency=currency)
    category_spend = {
        row.category: row.spent_minor_units
        for row in await store.get_category_spend(
            session, start=query.start, end=query.end, currency=currency
        )
    }
    budget_statuses = [
        BudgetStatusView(
            category=b.category,
            cap_minor_units=b.cap_minor_units,
            spent_minor_units=category_spend.get(b.category, 0),
            currency=b.currency,
            over_cap=category_spend.get(b.category, 0) > b.cap_minor_units,
        )
        for b in latest_budgets
    ]
    budgets_within_cap = sum(1 for b in budget_statuses if not b.over_cap)

    health_score = _savings_points(total_income, total_expense) + _budget_points(
        budgets_within_cap, len(budget_statuses)
    )

    return FinancialHealthView(
        tenant_id=query.tenant_id,
        period_start=query.start,
        period_end=query.end,
        generated_at=now,
        currency=currency,
        total_income_minor_units=total_income,
        total_expense_minor_units=total_expense,
        savings_rate=savings_rate,
        budgets=budget_statuses,
        health_score=health_score,
    )
