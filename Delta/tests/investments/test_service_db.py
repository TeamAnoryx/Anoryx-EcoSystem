"""D-023 non-stubbed investments service suite: real DB-backed record_holding +
get_allocation_recommendation composition, exact expected-value assertions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from delta.investments import service
from delta.investments.schemas import AllocationRecommendationQuery, HoldingRecordRequest
from delta.persistence.database import get_tenant_session
from delta.personal_finance import service as personal_finance_service
from delta.personal_finance import store as personal_finance_store
from delta.personal_finance.schemas import TransactionCreateRequest

from .conftest import db_required

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
_START = _NOW - timedelta(days=30)


async def _seed_investment_account(tenant_id: str, *, name: str = "Brokerage") -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await personal_finance_store.create_account(
            session, tenant_id=tenant_id, type="investment", currency="USD", name=name, now=_NOW
        )
        await session.commit()
    return account.account_id


async def _seed_checking_account(tenant_id: str) -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await personal_finance_store.create_account(
            session, tenant_id=tenant_id, type="checking", currency="USD", name="Checking", now=_NOW
        )
        await session.commit()
    return account.account_id


async def _record_holding(
    tenant_id: str, account_id: str, asset_class: str, value_minor_units: int
) -> None:
    async with get_tenant_session(tenant_id) as session:
        await service.record_holding(
            session,
            HoldingRecordRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                asset_class=asset_class,
                value_minor_units=value_minor_units,
                currency="USD",
            ),
            now=_NOW,
        )


@db_required
async def test_record_holding_against_unknown_account_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(service.AccountNotFoundError):
            await service.record_holding(
                session,
                HoldingRecordRequest(
                    tenant_id=tenant_id,
                    account_id="99999999-9999-4999-8999-999999999999",
                    asset_class="stocks",
                    value_minor_units=1000,
                    currency="USD",
                ),
                now=_NOW,
            )


@db_required
async def test_record_holding_against_other_tenants_account_raises(
    tenant_id, other_tenant_id
) -> None:
    account_id = await _seed_investment_account(tenant_id)

    async with get_tenant_session(other_tenant_id) as session:
        with pytest.raises(service.AccountNotFoundError):
            await service.record_holding(
                session,
                HoldingRecordRequest(
                    tenant_id=other_tenant_id,
                    account_id=account_id,
                    asset_class="stocks",
                    value_minor_units=1000,
                    currency="USD",
                ),
                now=_NOW,
            )


@db_required
async def test_record_holding_against_non_investment_account_raises(tenant_id) -> None:
    account_id = await _seed_checking_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(service.NotAnInvestmentAccountError):
            await service.record_holding(
                session,
                HoldingRecordRequest(
                    tenant_id=tenant_id,
                    account_id=account_id,
                    asset_class="stocks",
                    value_minor_units=1000,
                    currency="USD",
                ),
                now=_NOW,
            )


@db_required
async def test_allocation_recommendation_empty_portfolio_no_income_suggests_nothing(
    tenant_id,
) -> None:
    async with get_tenant_session(tenant_id) as session:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile="moderate", start=_START, end=_NOW
        )
        view = await service.get_allocation_recommendation(session, query, now=_NOW, currency="USD")

    assert view.total_portfolio_value_minor_units == 0
    assert view.suggested_contribution_minor_units == 0
    assert all(line.recommended_action == "hold" for line in view.lines)
    assert all(line.recommended_rebalance_minor_units == 0 for line in view.lines)
    assert all(line.current_pct is None and line.drift_pct is None for line in view.lines)


@db_required
async def test_allocation_recommendation_suggests_contribution_from_surplus(tenant_id) -> None:
    checking = await _seed_checking_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await personal_finance_service.create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=checking,
                category="income",
                amount_minor_units=200_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=5),
            ),
            now=_NOW,
        )
    async with get_tenant_session(tenant_id) as session:
        await personal_finance_service.create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=checking,
                category="groceries",
                amount_minor_units=-50_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=4),
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile="conservative", start=_START, end=_NOW
        )
        view = await service.get_allocation_recommendation(session, query, now=_NOW, currency="USD")

    # surplus = 200_000 - 50_000 = 150_000; 20% contribution rate -> 30_000
    assert view.suggested_contribution_minor_units == 30_000
    # the per-class split sums exactly back to the total (largest-remainder method)
    assert sum(line.suggested_contribution_minor_units for line in view.lines) == 30_000
    # conservative profile weights bonds heaviest (0.60)
    bonds_line = next(line for line in view.lines if line.asset_class == "bonds")
    assert bonds_line.suggested_contribution_minor_units == 18_000


@db_required
async def test_allocation_recommendation_no_surplus_suggests_nothing(tenant_id) -> None:
    checking = await _seed_checking_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await personal_finance_service.create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=checking,
                category="income",
                amount_minor_units=50_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=5),
            ),
            now=_NOW,
        )
    async with get_tenant_session(tenant_id) as session:
        await personal_finance_service.create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=checking,
                category="rent",
                amount_minor_units=-80_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=4),
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile="moderate", start=_START, end=_NOW
        )
        view = await service.get_allocation_recommendation(session, query, now=_NOW, currency="USD")

    assert view.suggested_contribution_minor_units == 0


@db_required
async def test_allocation_recommendation_flags_overweight_and_underweight(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    # Portfolio entirely in stocks: $10,000. Conservative target for stocks is 10%,
    # so this is massively overweight stocks and underweight everything else.
    await _record_holding(tenant_id, account_id, "stocks", 1_000_000)

    async with get_tenant_session(tenant_id) as session:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile="conservative", start=_START, end=_NOW
        )
        view = await service.get_allocation_recommendation(session, query, now=_NOW, currency="USD")

    assert view.total_portfolio_value_minor_units == 1_000_000
    stocks_line = next(line for line in view.lines if line.asset_class == "stocks")
    bonds_line = next(line for line in view.lines if line.asset_class == "bonds")
    assert stocks_line.recommended_action == "sell"
    assert stocks_line.current_pct == 1.0
    assert bonds_line.recommended_action == "buy"
    assert bonds_line.current_value_minor_units == 0


@db_required
async def test_allocation_recommendation_within_threshold_holds(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    # Conservative target: stocks 10%, bonds 60%, cash_equivalents 25%, real_estate 5%.
    # Fund exactly on-target -> every line should be 'hold'.
    await _record_holding(tenant_id, account_id, "stocks", 100_000)
    await _record_holding(tenant_id, account_id, "bonds", 600_000)
    await _record_holding(tenant_id, account_id, "cash_equivalents", 250_000)
    await _record_holding(tenant_id, account_id, "real_estate", 50_000)

    async with get_tenant_session(tenant_id) as session:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile="conservative", start=_START, end=_NOW
        )
        view = await service.get_allocation_recommendation(session, query, now=_NOW, currency="USD")

    assert view.total_portfolio_value_minor_units == 1_000_000
    assert all(line.recommended_action == "hold" for line in view.lines)
    assert all(line.recommended_rebalance_minor_units == 0 for line in view.lines)


@db_required
async def test_allocation_recommendation_currency_scoped(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await service.record_holding(
            session,
            HoldingRecordRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                asset_class="stocks",
                value_minor_units=999_999,
                currency="EUR",
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        query = AllocationRecommendationQuery(
            tenant_id=tenant_id, risk_profile="moderate", start=_START, end=_NOW
        )
        view = await service.get_allocation_recommendation(session, query, now=_NOW, currency="USD")

    # EUR holding is excluded from a USD-scoped report — never silently mixed in.
    assert view.total_portfolio_value_minor_units == 0
