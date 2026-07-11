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


@db_required
async def test_get_latest_holdings_unscoped_keeps_same_class_in_different_currencies(
    tenant_id,
) -> None:
    # Security audit finding: grouping "latest per pair" by (account_id,
    # asset_class) only — without currency — silently hid the older currency's row
    # behind the newer one's MAX(created_at) when an account holds the SAME asset
    # class in two currencies. currency must be part of the grouping key.
    account_id = await _seed_investment_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=100_000,
            currency="USD",
            now=_NOW - timedelta(days=1),
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            asset_class="stocks",
            value_minor_units=50_000,
            currency="EUR",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        holdings = await store.get_latest_holdings(session)

    assert {(h.currency, h.value_minor_units) for h in holdings} == {
        ("USD", 100_000),
        ("EUR", 50_000),
    }


@db_required
async def test_get_total_value_by_asset_class_sums_across_accounts(tenant_id) -> None:
    account_a = await _seed_investment_account(tenant_id, name="Brokerage A")
    account_b = await _seed_investment_account(tenant_id, name="Brokerage B")

    async with get_tenant_session(tenant_id) as session:
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_a,
            asset_class="stocks",
            value_minor_units=100_000,
            currency="USD",
            now=_NOW,
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_b,
            asset_class="stocks",
            value_minor_units=200_000,
            currency="USD",
            now=_NOW,
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_a,
            asset_class="bonds",
            value_minor_units=50_000,
            currency="USD",
            now=_NOW,
        )
        # Excluded: different currency, and a superseded (non-latest) snapshot.
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_a,
            asset_class="crypto",
            value_minor_units=999_999,
            currency="EUR",
            now=_NOW,
        )
        await store.create_holding(
            session,
            tenant_id=tenant_id,
            account_id=account_a,
            asset_class="stocks",
            value_minor_units=1,
            currency="USD",
            now=_NOW - timedelta(days=1),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        totals = await store.get_total_value_by_asset_class(session, currency="USD")

    assert totals == {"stocks": 300_000, "bonds": 50_000}


@db_required
async def test_get_total_value_by_asset_class_sums_only_the_latest_snapshot(tenant_id) -> None:
    # get_total_value_by_asset_class is a genuine SQL aggregate with no .limit()
    # clause of its own (security audit finding: the old code path computed the
    # portfolio total via the LIST query, which IS capped at MAX_LIST_LIMIT and
    # would silently truncate a large portfolio). This proves it still follows the
    # same "one row per (account, asset_class, currency)" insert-only semantics as
    # get_latest_holdings — many superseded snapshots never inflate the sum.
    account_id = await _seed_investment_account(tenant_id)
    count = 20

    async with get_tenant_session(tenant_id) as session:
        for i in range(count):
            await store.create_holding(
                session,
                tenant_id=tenant_id,
                account_id=account_id,
                asset_class="other",
                value_minor_units=1,
                currency="USD",
                now=_NOW - timedelta(seconds=count - i),
            )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        # Only the LATEST "other" snapshot for this one account counts (insert-only
        # semantics) — this proves the aggregate follows the same latest-per-pair
        # rule as get_latest_holdings, not that N snapshots sum together.
        totals = await store.get_total_value_by_asset_class(session, currency="USD")

    assert totals == {"other": 1}
