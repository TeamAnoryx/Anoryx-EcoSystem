"""Asset-allocation recommendation orchestration (D-023, ADR-0023).

`create_recommendation` computes a DETERMINISTIC target-allocation percentage split
(from the fixed `RISK_TIER_TARGET_ALLOCATION_PCT` table) plus a recommended one-time
micro-investment amount (a fixed `MICRO_INVESTMENT_SURPLUS_RATE_BPS` of the tenant's
net surplus over the caller's window, floored to 0 whenever that surplus is not
positive).
This is plain arithmetic over a fixed table and a caller-declared risk tier — NOT
machine learning or AI, NOT a live market-data feed, and NOT real investment execution
(mirrors D-011/D-012's "AI-sounding roadmap name, disclosed deterministic heuristic"
precedent). See ADR-0023 §2 for the full decision record and honesty boundary.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from . import store
from .schemas import (
    MICRO_INVESTMENT_SURPLUS_RATE_BPS,
    RISK_TIER_TARGET_ALLOCATION_PCT,
    AllocationRecommendationRequest,
    AllocationRecommendationView,
    RiskTierAllocationView,
)

_METHOD = "risk_tier_target_allocation_v1"
_BPS_DENOMINATOR = 10_000


class AccountNotFoundError(Exception):
    pass


class AccountNotInvestmentTypeError(Exception):
    pass


def list_risk_tiers() -> list[RiskTierAllocationView]:
    """Pure, no-DB: the disclosed target-allocation table for every risk tier."""
    return [
        RiskTierAllocationView(risk_tier=tier, **pcts)
        for tier, pcts in RISK_TIER_TARGET_ALLOCATION_PCT.items()
    ]


def _recommended_micro_investment_minor_units(surplus_minor_units: int) -> int:
    if surplus_minor_units <= 0:
        return 0
    # Exact integer arithmetic (money.py: floats are forbidden in any monetary
    # computation). `//` floors a nonnegative numerator — never recommends more than
    # MICRO_INVESTMENT_SURPLUS_RATE_BPS / 10_000 of the surplus actually observed, at
    # any magnitude (no float-precision edge case, unlike a float-rate multiplication).
    return (surplus_minor_units * MICRO_INVESTMENT_SURPLUS_RATE_BPS) // _BPS_DENOMINATOR


def _to_view(record: store.RecommendationRecord) -> AllocationRecommendationView:
    return AllocationRecommendationView(
        recommendation_id=record.recommendation_id,
        tenant_id=record.tenant_id,
        account_id=record.account_id,
        risk_tier=record.risk_tier,  # type: ignore[arg-type]
        cash_pct=record.cash_pct,
        bonds_pct=record.bonds_pct,
        equities_pct=record.equities_pct,
        period_start=record.period_start,
        period_end=record.period_end,
        surplus_minor_units=record.surplus_minor_units,
        recommended_micro_investment_minor_units=record.recommended_micro_investment_minor_units,
        currency=record.currency,
        method=record.method,  # type: ignore[arg-type]
        computed_at=record.computed_at,
    )


async def create_recommendation(
    session: AsyncSession, req: AllocationRecommendationRequest, *, now: datetime
) -> AllocationRecommendationView:
    account = await store.get_account(session, account_id=req.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        raise AccountNotFoundError(req.account_id)
    if account.type != "investment":
        raise AccountNotInvestmentTypeError(req.account_id)

    surplus = await store.get_net_surplus_minor_units(
        session, start=req.period_start, end=req.period_end, currency=account.currency
    )
    micro_investment = _recommended_micro_investment_minor_units(surplus)
    allocation = RISK_TIER_TARGET_ALLOCATION_PCT[req.risk_tier]

    record = await store.create_recommendation(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        risk_tier=req.risk_tier,
        cash_pct=allocation["cash_pct"],
        bonds_pct=allocation["bonds_pct"],
        equities_pct=allocation["equities_pct"],
        period_start=req.period_start,
        period_end=req.period_end,
        surplus_minor_units=surplus,
        recommended_micro_investment_minor_units=micro_investment,
        currency=account.currency,
        method=_METHOD,
        now=now,
    )
    await session.commit()
    return _to_view(record)


async def list_recommendation_views(
    session: AsyncSession, *, account_id: str | None, limit: int
) -> list[AllocationRecommendationView]:
    records = await store.list_recommendations(session, account_id=account_id, limit=limit)
    return [_to_view(r) for r in records]
