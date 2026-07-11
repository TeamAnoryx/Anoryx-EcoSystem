"""Asset-allocation persistence (D-023, ADR-0023).

Tenant-scoped reads/writes against `personal_allocation_recommendations` (migration
0016) plus a read of D-021's `personal_accounts`/`personal_transactions`. Every
function takes an already-open :class:`AsyncSession` (from
`delta.persistence.database.get_tenant_session`) and does NOT commit — the caller
(`service.py`) owns the transaction, exactly like `personal_finance.store`.

Queries `personal_accounts`/`personal_transactions` directly rather than importing
`delta.personal_finance.store` (ADR-0022 Fork 7 precedent: read a shared table
directly, don't couple a new package to another feature's store-module interface).
No explicit `tenant_id` filter appears in any WHERE clause below — every query runs on
a tenant-scoped RLS session (the strict fail-closed NULLIF predicate, migration 0014/
0016), exactly like every function in `personal_finance.store`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import (
    personal_accounts,
    personal_allocation_recommendations,
    personal_transactions,
)

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
class RecommendationRecord:
    recommendation_id: str
    tenant_id: str
    account_id: str
    risk_tier: str
    cash_pct: int
    bonds_pct: int
    equities_pct: int
    period_start: datetime
    period_end: datetime
    surplus_minor_units: int
    recommended_micro_investment_minor_units: int
    currency: str
    method: str
    computed_at: datetime


def _account_from_row(row) -> AccountRecord:
    return AccountRecord(
        account_id=row.account_id,
        tenant_id=row.tenant_id,
        type=row.type,
        currency=row.currency,
        name=row.name,
        created_at=row.created_at,
    )


def _recommendation_from_row(row) -> RecommendationRecord:
    return RecommendationRecord(
        recommendation_id=row.recommendation_id,
        tenant_id=row.tenant_id,
        account_id=row.account_id,
        risk_tier=row.risk_tier,
        cash_pct=row.cash_pct,
        bonds_pct=row.bonds_pct,
        equities_pct=row.equities_pct,
        period_start=row.period_start,
        period_end=row.period_end,
        surplus_minor_units=row.surplus_minor_units,
        recommended_micro_investment_minor_units=row.recommended_micro_investment_minor_units,
        currency=row.currency,
        method=row.method,
        computed_at=row.computed_at,
    )


async def get_account(session: AsyncSession, *, account_id: str) -> AccountRecord | None:
    stmt = select(personal_accounts).where(personal_accounts.c.account_id == account_id)
    row = (await session.execute(stmt)).first()
    return _account_from_row(row) if row is not None else None


async def get_net_surplus_minor_units(
    session: AsyncSession, *, start: datetime, end: datetime, currency: str
) -> int:
    """Net income-minus-expense across every `personal_transactions` row in
    `[start, end)`, scoped to one currency (D-001's no-FX rule).

    `amount_minor_units` is already signed (positive = income, negative = expense —
    same convention `personal_finance.store` uses), so a plain SUM is the net surplus
    directly; no separate income/expense totals are needed for this one figure
    (unlike `personal_finance.get_financial_health`, which needs both to score savings
    AND budget adherence separately).
    """
    stmt = select(func.coalesce(func.sum(personal_transactions.c.amount_minor_units), 0)).where(
        personal_transactions.c.currency == currency,
        personal_transactions.c.occurred_at >= start,
        personal_transactions.c.occurred_at < end,
    )
    return int((await session.execute(stmt)).scalar_one())


async def create_recommendation(
    session: AsyncSession,
    *,
    tenant_id: str,
    account_id: str,
    risk_tier: str,
    cash_pct: int,
    bonds_pct: int,
    equities_pct: int,
    period_start: datetime,
    period_end: datetime,
    surplus_minor_units: int,
    recommended_micro_investment_minor_units: int,
    currency: str,
    method: str,
    now: datetime,
) -> RecommendationRecord:
    recommendation_id = str(uuid.uuid4())
    await session.execute(
        insert(personal_allocation_recommendations).values(
            recommendation_id=recommendation_id,
            tenant_id=tenant_id,
            account_id=account_id,
            risk_tier=risk_tier,
            cash_pct=cash_pct,
            bonds_pct=bonds_pct,
            equities_pct=equities_pct,
            period_start=period_start,
            period_end=period_end,
            surplus_minor_units=surplus_minor_units,
            recommended_micro_investment_minor_units=recommended_micro_investment_minor_units,
            currency=currency,
            method=method,
            computed_at=now,
        )
    )
    return RecommendationRecord(
        recommendation_id=recommendation_id,
        tenant_id=tenant_id,
        account_id=account_id,
        risk_tier=risk_tier,
        cash_pct=cash_pct,
        bonds_pct=bonds_pct,
        equities_pct=equities_pct,
        period_start=period_start,
        period_end=period_end,
        surplus_minor_units=surplus_minor_units,
        recommended_micro_investment_minor_units=recommended_micro_investment_minor_units,
        currency=currency,
        method=method,
        computed_at=now,
    )


async def list_recommendations(
    session: AsyncSession,
    *,
    account_id: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[RecommendationRecord]:
    stmt = select(personal_allocation_recommendations)
    if account_id is not None:
        stmt = stmt.where(personal_allocation_recommendations.c.account_id == account_id)
    stmt = stmt.order_by(personal_allocation_recommendations.c.computed_at.desc()).limit(
        _clamp_limit(limit)
    )
    rows = (await session.execute(stmt)).all()
    return [_recommendation_from_row(r) for r in rows]
