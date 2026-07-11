"""D-023 service-layer DB tests: account-type gating, the deterministic surplus ->
micro-investment formula against real recorded transactions (never hand-computed), and
exception mapping.

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as
``tests/subscriptions/test_service_db.py``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from delta.asset_allocation.schemas import AllocationRecommendationRequest
from delta.asset_allocation.service import (
    AccountNotFoundError,
    AccountNotInvestmentTypeError,
    create_recommendation,
    list_recommendation_views,
)
from delta.persistence.database import get_tenant_session
from delta.personal_finance import store as pf_store

from .conftest import db_required

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)


async def _seed_account(tenant_id: str, *, type: str) -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await pf_store.create_account(
            session, tenant_id=tenant_id, type=type, currency="USD", name="Acct", now=_NOW
        )
        await session.commit()
    return account.account_id


async def _seed_transaction(tenant_id: str, account_id: str, amount_minor_units: int) -> None:
    async with get_tenant_session(tenant_id) as session:
        await pf_store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="income" if amount_minor_units > 0 else "other",
            amount_minor_units=amount_minor_units,
            currency="USD",
            description="seed",
            merchant=None,
            occurred_at=_NOW - timedelta(days=5),
            now=_NOW,
        )
        await session.commit()


@db_required
async def test_recommendation_against_missing_account_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await create_recommendation(
                session,
                AllocationRecommendationRequest(
                    tenant_id=tenant_id,
                    account_id="99999999-9999-4999-8999-999999999999",
                    risk_tier="moderate",
                    period_start=_NOW - timedelta(days=30),
                    period_end=_NOW,
                ),
                now=_NOW,
            )


@db_required
async def test_recommendation_against_non_investment_account_raises(tenant_id) -> None:
    account_id = await _seed_account(tenant_id, type="checking")
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotInvestmentTypeError):
            await create_recommendation(
                session,
                AllocationRecommendationRequest(
                    tenant_id=tenant_id,
                    account_id=account_id,
                    risk_tier="moderate",
                    period_start=_NOW - timedelta(days=30),
                    period_end=_NOW,
                ),
                now=_NOW,
            )


@db_required
async def test_recommendation_against_another_tenants_account_raises(
    tenant_id, other_tenant_id
) -> None:
    account_id = await _seed_account(tenant_id, type="investment")
    async with get_tenant_session(other_tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await create_recommendation(
                session,
                AllocationRecommendationRequest(
                    tenant_id=other_tenant_id,
                    account_id=account_id,
                    risk_tier="moderate",
                    period_start=_NOW - timedelta(days=30),
                    period_end=_NOW,
                ),
                now=_NOW,
            )


@db_required
async def test_positive_surplus_recommends_ten_percent_micro_investment(tenant_id) -> None:
    account_id = await _seed_account(tenant_id, type="investment")
    await _seed_transaction(tenant_id, account_id, 1000_00)  # income
    await _seed_transaction(tenant_id, account_id, -400_00)  # expense
    # net surplus = 600.00 -> 10% = 60.00

    async with get_tenant_session(tenant_id) as session:
        view = await create_recommendation(
            session,
            AllocationRecommendationRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                risk_tier="aggressive",
                period_start=_NOW - timedelta(days=30),
                period_end=_NOW,
            ),
            now=_NOW,
        )

    assert view.surplus_minor_units == 600_00
    assert view.recommended_micro_investment_minor_units == 60_00
    assert view.cash_pct == 10
    assert view.bonds_pct == 15
    assert view.equities_pct == 75
    assert view.cash_pct + view.bonds_pct + view.equities_pct == 100
    assert view.method == "risk_tier_target_allocation_v1"


@db_required
async def test_negative_surplus_recommends_zero_never_negative(tenant_id) -> None:
    account_id = await _seed_account(tenant_id, type="investment")
    await _seed_transaction(tenant_id, account_id, 100_00)  # income
    await _seed_transaction(tenant_id, account_id, -500_00)  # expense
    # net surplus = -400.00 -> recommendation floors to 0, never negative.

    async with get_tenant_session(tenant_id) as session:
        view = await create_recommendation(
            session,
            AllocationRecommendationRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                risk_tier="conservative",
                period_start=_NOW - timedelta(days=30),
                period_end=_NOW,
            ),
            now=_NOW,
        )

    assert view.surplus_minor_units == -400_00
    assert view.recommended_micro_investment_minor_units == 0


@db_required
async def test_zero_surplus_recommends_zero(tenant_id) -> None:
    account_id = await _seed_account(tenant_id, type="investment")
    # No transactions recorded at all in the window.

    async with get_tenant_session(tenant_id) as session:
        view = await create_recommendation(
            session,
            AllocationRecommendationRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                risk_tier="moderate",
                period_start=_NOW - timedelta(days=30),
                period_end=_NOW,
            ),
            now=_NOW,
        )

    assert view.surplus_minor_units == 0
    assert view.recommended_micro_investment_minor_units == 0


@db_required
async def test_micro_investment_floors_toward_zero_never_overrecommends(tenant_id) -> None:
    account_id = await _seed_account(tenant_id, type="investment")
    await _seed_transaction(tenant_id, account_id, 101)  # surplus = 101 minor units
    # 10% of 101 = 10.1 -> must floor to 10, never round up to 11.

    async with get_tenant_session(tenant_id) as session:
        view = await create_recommendation(
            session,
            AllocationRecommendationRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                risk_tier="moderate",
                period_start=_NOW - timedelta(days=30),
                period_end=_NOW,
            ),
            now=_NOW,
        )

    assert view.surplus_minor_units == 101
    assert view.recommended_micro_investment_minor_units == 10


@db_required
async def test_list_recommendation_views_roundtrip(tenant_id) -> None:
    account_id = await _seed_account(tenant_id, type="investment")
    async with get_tenant_session(tenant_id) as session:
        await create_recommendation(
            session,
            AllocationRecommendationRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                risk_tier="moderate",
                period_start=_NOW - timedelta(days=30),
                period_end=_NOW,
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        views = await list_recommendation_views(session, account_id=account_id, limit=100)

    assert len(views) == 1
    assert views[0].account_id == account_id
