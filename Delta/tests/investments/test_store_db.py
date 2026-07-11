"""D-023 non-stubbed investment-holdings persistence suite: real store writes -> real
SQL reads, real RLS."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.investments import store
from delta.persistence.database import get_tenant_session
from delta.personal_finance import store as personal_finance_store

from .conftest import db_required

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)


async def _seed_investment_account(tenant_id: str, *, name: str = "Brokerage") -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await personal_finance_store.create_account(
            session, tenant_id=tenant_id, type="investment", currency="USD", name=name, now=_NOW
        )
        await session.commit()
    return account.account_id


@db_required
async def test_create_and_list_holding_roundtrip(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=500_000,
            currency="USD",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        holdings = await store.get_latest_holdings(session)

    assert len(holdings) == 1
    assert holdings[0].asset_class == "stocks"
    assert holdings[0].value_minor_units == 500_000


@db_required
async def test_get_latest_holdings_returns_most_recent_per_account_and_class(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=400_000,
            currency="USD",
            now=_NOW - timedelta(days=10),
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=450_000,
            currency="USD",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        holdings = await store.get_latest_holdings(session)

    assert len(holdings) == 1
    assert holdings[0].value_minor_units == 450_000  # the newer snapshot wins


@db_required
async def test_get_latest_holdings_sums_across_multiple_accounts(tenant_id) -> None:
    account_a = await _seed_investment_account(tenant_id, name="Brokerage A")
    account_b = await _seed_investment_account(tenant_id, name="Brokerage B")

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_a,
            asset_class="bonds",
            value_minor_units=100_000,
            currency="USD",
            now=_NOW,
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_b,
            asset_class="bonds",
            value_minor_units=200_000,
            currency="USD",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        holdings = await store.get_latest_holdings(session)

    assert {h.account_id for h in holdings} == {account_a, account_b}
    assert sum(h.value_minor_units for h in holdings) == 300_000


@db_required
async def test_get_latest_holdings_currency_scoped(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=100_000,
            currency="EUR",
            now=_NOW,
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="bonds",
            value_minor_units=50_000,
            currency="USD",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        usd_only = await store.get_latest_holdings(session, currency="USD")
        all_currencies = await store.get_latest_holdings(session)

    assert [h.asset_class for h in usd_only] == ["bonds"]
    assert {h.asset_class for h in all_currencies} == {"stocks", "bonds"}


@db_required
async def test_get_latest_holdings_filters_by_account(tenant_id) -> None:
    account_a = await _seed_investment_account(tenant_id, name="Brokerage A")
    account_b = await _seed_investment_account(tenant_id, name="Brokerage B")

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_a,
            asset_class="crypto",
            value_minor_units=10_000,
            currency="USD",
            now=_NOW,
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_b,
            asset_class="crypto",
            value_minor_units=20_000,
            currency="USD",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        scoped = await store.get_latest_holdings(session, account_id=account_a)

    assert len(scoped) == 1
    assert scoped[0].account_id == account_a


@db_required
async def test_cross_tenant_isolation(tenant_id, other_tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=100_000,
            currency="USD",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        holdings = await store.get_latest_holdings(session)

    assert holdings == []
