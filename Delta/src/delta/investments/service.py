"""Personal asset allocation + micro-investment recommendation orchestration
(D-023, ADR-0023).

``get_allocation_recommendation`` composes two independently-computed, disclosed,
DETERMINISTIC heuristics — NOT machine learning or AI, NOT live market data (mirrors
D-021's health-score / D-011's forecasting honesty convention):

- **Rebalancing lines**: each asset class's current holding value (the latest
  self-reported snapshot per (account, asset class), summed across every
  `investment`-type account) is compared against a FIXED target weight for the
  caller's risk profile (see ``_TARGET_ALLOCATIONS`` below — three canonical
  profiles, weights sum to exactly 1.0 each). A class whose drift exceeds
  ``_DRIFT_THRESHOLD_PCT`` gets a buy/sell suggestion sized to close the drift; a
  portfolio with zero recorded holdings cannot be rebalanced (every line is
  ``hold``, amount 0 — a missing signal is scored as absent, never assumed
  favorable, the same rule ADR-0021 §2 Fork 6 applies to the health score).
- **Suggested contribution**: ``_CONTRIBUTION_RATE`` (20%) of the queried window's
  income-minus-expense surplus (reusing D-021's own
  ``personal_finance.store.get_income_expense_totals`` — no duplicate query logic),
  floored at 0 (no income recorded, or spend outstripping income, suggests nothing),
  split across asset classes by the SAME fixed target weights via a largest-
  remainder allocation so the per-class amounts always sum exactly to the total.

No live market data, no trade execution, no brokerage/exchange integration of any
kind exists anywhere in this codebase — every number here is advisory arithmetic
over caller-declared holdings and Delta's own ledger (ADR-0023 Sec 1).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from ..personal_finance import store as personal_finance_store
from . import store
from .schemas import (
    ASSET_CLASSES,
    AllocationLineView,
    AllocationRecommendationQuery,
    AllocationRecommendationView,
    HoldingRecordRequest,
    HoldingView,
)

# Three canonical, disclosed target-allocation models. Each MUST sum to exactly
# 1.0 (enforced by a module-load assertion below, and by
# test_schemas.py::test_target_allocations_sum_to_one).
_TARGET_ALLOCATIONS: dict[str, dict[str, float]] = {
    "conservative": {
        "stocks": 0.10,
        "bonds": 0.60,
        "cash_equivalents": 0.25,
        "real_estate": 0.05,
        "crypto": 0.00,
        "other": 0.00,
    },
    "moderate": {
        "stocks": 0.45,
        "bonds": 0.35,
        "real_estate": 0.10,
        "cash_equivalents": 0.08,
        "crypto": 0.02,
        "other": 0.00,
    },
    "aggressive": {
        "stocks": 0.70,
        "real_estate": 0.15,
        "crypto": 0.10,
        "bonds": 0.05,
        "cash_equivalents": 0.00,
        "other": 0.00,
    },
}


def _validate_target_allocations(allocations: dict[str, dict[str, float]]) -> None:
    for profile, weights in allocations.items():
        if set(weights) != set(ASSET_CLASSES):
            raise ValueError(f"{profile} must weight every asset class")
        if abs(sum(weights.values()) - 1.0) >= 1e-9:
            raise ValueError(f"{profile} weights must sum to 1.0")


_validate_target_allocations(_TARGET_ALLOCATIONS)

# A drift below this magnitude (1 percentage point) is treated as noise, not a
# rebalance-worthy signal — mirrors D-012's fixed anomaly-ratio threshold discipline
# (a library default, not a caller-tunable knob).
_DRIFT_THRESHOLD_PCT = 0.01

# What fraction of a window's income-minus-expense surplus is suggested as a new
# investment contribution. A module constant, not a caller-tunable parameter — same
# "a safety/advisory default a caller cannot override in the same request" posture
# D-024 applies to its execution caps.
_CONTRIBUTION_RATE = 0.20


class AccountNotFoundError(LookupError):
    pass


class NotAnInvestmentAccountError(ValueError):
    """The account exists but is not a D-021 `investment`-type account."""


def _holding_view(record: store.HoldingRecord) -> HoldingView:
    return HoldingView(
        holding_id=record.holding_id,
        tenant_id=record.tenant_id,
        account_id=record.account_id,
        asset_class=record.asset_class,  # type: ignore[arg-type]
        value_minor_units=record.value_minor_units,
        currency=record.currency,
        created_at=record.created_at,
    )


async def record_holding(
    session: AsyncSession, req: HoldingRecordRequest, *, now: datetime
) -> HoldingView:
    account = await personal_finance_store.get_account(session, account_id=req.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        raise AccountNotFoundError(req.account_id)
    if account.type != "investment":
        raise NotAnInvestmentAccountError(req.account_id)
    record = await store.create_holding(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        asset_class=req.asset_class,
        value_minor_units=req.value_minor_units,
        currency=req.currency,
        now=now,
    )
    await session.commit()
    return _holding_view(record)


async def list_holding_views(
    session: AsyncSession, *, account_id: str | None, limit: int
) -> list[HoldingView]:
    records = await store.get_latest_holdings(session, account_id=account_id, limit=limit)
    return [_holding_view(r) for r in records]


def _split_by_weights(total: int, weights: dict[str, float]) -> dict[str, int]:
    """Split ``total`` minor units across ``weights`` so the parts sum EXACTLY to
    ``total`` (largest-remainder method) — a naive per-class ``round()`` can drift
    the sum off by a unit or two, which would silently misstate a monetary total."""
    raw = {k: total * w for k, w in weights.items()}
    floors = {k: int(v) for k, v in raw.items()}
    remainder = total - sum(floors.values())
    ranked = sorted(raw, key=lambda k: raw[k] - floors[k], reverse=True)
    result = dict(floors)
    for k in ranked[:remainder]:
        result[k] += 1
    return result


async def get_allocation_recommendation(
    session: AsyncSession,
    query: AllocationRecommendationQuery,
    *,
    now: datetime,
    currency: str,
) -> AllocationRecommendationView:
    holdings = await store.get_latest_holdings(
        session, currency=currency, limit=store.MAX_LIST_LIMIT
    )
    value_by_class: dict[str, int] = {ac: 0 for ac in ASSET_CLASSES}
    for h in holdings:
        value_by_class[h.asset_class] += h.value_minor_units
    total_value = sum(value_by_class.values())

    target_weights = _TARGET_ALLOCATIONS[query.risk_profile]

    total_income, total_expense = await personal_finance_store.get_income_expense_totals(
        session, start=query.start, end=query.end, currency=currency
    )
    # Missing/absent signal (no income recorded) suggests nothing — never assumed
    # favorable (ADR-0021 §2 Fork 6's convention, applied here).
    surplus = total_income - total_expense if total_income > 0 else 0
    suggested_total = max(0, round(surplus * _CONTRIBUTION_RATE))
    contribution_split = _split_by_weights(suggested_total, target_weights)

    lines: list[AllocationLineView] = []
    for asset_class in ASSET_CLASSES:
        current_value = value_by_class[asset_class]
        target_pct = target_weights[asset_class]
        if total_value <= 0:
            current_pct = None
            drift_pct = None
            action = "hold"
            rebalance_amount = 0
        else:
            current_pct = current_value / total_value
            drift_pct = target_pct - current_pct
            if abs(drift_pct) < _DRIFT_THRESHOLD_PCT:
                action = "hold"
                rebalance_amount = 0
            elif drift_pct > 0:
                action = "buy"
                rebalance_amount = round(drift_pct * total_value)
            else:
                action = "sell"
                rebalance_amount = round(abs(drift_pct) * total_value)
        lines.append(
            AllocationLineView(
                asset_class=asset_class,  # type: ignore[arg-type]
                current_value_minor_units=current_value,
                current_pct=current_pct,
                target_pct=target_pct,
                drift_pct=drift_pct,
                recommended_action=action,  # type: ignore[arg-type]
                recommended_rebalance_minor_units=rebalance_amount,
                suggested_contribution_minor_units=contribution_split[asset_class],
            )
        )

    return AllocationRecommendationView(
        tenant_id=query.tenant_id,
        risk_profile=query.risk_profile,
        generated_at=now,
        currency=currency,
        total_portfolio_value_minor_units=total_value,
        lines=lines,
        suggested_contribution_minor_units=suggested_total,
    )
