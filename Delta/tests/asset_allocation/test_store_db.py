"""D-023 non-stubbed asset-allocation persistence suite: real store writes -> real SQL
reads, real RLS, real FK/CHECK constraints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from delta.asset_allocation import store
from delta.persistence.database import get_privileged_session, get_tenant_session
from delta.personal_finance import store as pf_store

from .conftest import db_required

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)


async def _seed_investment_account(tenant_id: str) -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await pf_store.create_account(
            session,
            tenant_id=tenant_id,
            type="investment",
            currency="USD",
            name="Brokerage",
            now=_NOW,
        )
        await session.commit()
    return account.account_id


@db_required
async def test_get_account_roundtrip(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        account = await store.get_account(session, account_id=account_id)
    assert account is not None
    assert account.type == "investment"
    assert account.currency == "USD"


@db_required
async def test_get_account_missing_returns_none(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        account = await store.get_account(
            session, account_id="99999999-9999-4999-8999-999999999999"
        )
    assert account is None


@db_required
async def test_net_surplus_sums_signed_amounts_in_window(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await pf_store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="income",
            amount_minor_units=500_00,
            currency="USD",
            description="paycheck",
            merchant=None,
            occurred_at=_NOW - timedelta(days=5),
            now=_NOW,
        )
        await pf_store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="groceries",
            amount_minor_units=-100_00,
            currency="USD",
            description="groceries",
            merchant=None,
            occurred_at=_NOW - timedelta(days=3),
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        surplus = await store.get_net_surplus_minor_units(
            session, start=_NOW - timedelta(days=30), end=_NOW, currency="USD"
        )
    assert surplus == 400_00


@db_required
async def test_net_surplus_excludes_transactions_outside_window(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await pf_store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="income",
            amount_minor_units=1000_00,
            currency="USD",
            description="old paycheck",
            merchant=None,
            occurred_at=_NOW - timedelta(days=400),
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        surplus = await store.get_net_surplus_minor_units(
            session, start=_NOW - timedelta(days=30), end=_NOW, currency="USD"
        )
    assert surplus == 0


@db_required
async def test_create_and_list_recommendation_roundtrip(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await store.create_recommendation(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            risk_tier="moderate",
            cash_pct=20,
            bonds_pct=30,
            equities_pct=50,
            period_start=_NOW - timedelta(days=30),
            period_end=_NOW,
            surplus_minor_units=400_00,
            recommended_micro_investment_minor_units=40_00,
            currency="USD",
            method="risk_tier_target_allocation_v1",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        recs = await store.list_recommendations(session, account_id=account_id)
    assert len(recs) == 1
    assert recs[0].risk_tier == "moderate"
    assert recs[0].recommended_micro_investment_minor_units == 40_00


@db_required
async def test_recommendation_against_nonexistent_account_violates_fk(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(IntegrityError):
            await store.create_recommendation(
                session,
                tenant_id=tenant_id,
                account_id="99999999-9999-4999-8999-999999999999",
                risk_tier="moderate",
                cash_pct=20,
                bonds_pct=30,
                equities_pct=50,
                period_start=_NOW - timedelta(days=30),
                period_end=_NOW,
                surplus_minor_units=0,
                recommended_micro_investment_minor_units=0,
                currency="USD",
                method="risk_tier_target_allocation_v1",
                now=_NOW,
            )


@db_required
async def test_cross_tenant_recommendation_list_isolated(tenant_id, other_tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        await store.create_recommendation(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            risk_tier="aggressive",
            cash_pct=10,
            bonds_pct=15,
            equities_pct=75,
            period_start=_NOW - timedelta(days=30),
            period_end=_NOW,
            surplus_minor_units=100_00,
            recommended_micro_investment_minor_units=10_00,
            currency="USD",
            method="risk_tier_target_allocation_v1",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        recs = await store.list_recommendations(session)
    assert recs == []


@db_required
async def test_recommendations_table_has_no_update_delete_grant(tenant_id) -> None:
    account_id = await _seed_investment_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        rec = await store.create_recommendation(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            risk_tier="conservative",
            cash_pct=40,
            bonds_pct=40,
            equities_pct=20,
            period_start=_NOW - timedelta(days=30),
            period_end=_NOW,
            surplus_minor_units=0,
            recommended_micro_investment_minor_units=0,
            currency="USD",
            method="risk_tier_target_allocation_v1",
            now=_NOW,
        )
        await session.commit()

    async with get_privileged_session() as session:
        rows = (
            (
                await session.execute(
                    text(
                        "SELECT privilege_type FROM information_schema.role_table_grants "
                        "WHERE table_schema = 'delta' AND "
                        "table_name = 'personal_allocation_recommendations' AND "
                        "grantee = 'delta_app'"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert set(rows) == {"SELECT", "INSERT"}
    assert rec.recommendation_id is not None
