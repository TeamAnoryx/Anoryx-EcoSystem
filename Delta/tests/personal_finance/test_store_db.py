"""D-021 non-stubbed personal-finance persistence suite: real store writes -> real SQL
reads, real RLS."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from delta.persistence.database import get_tenant_session
from delta.personal_finance import store

from .conftest import db_required

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


async def _seed_account(tenant_id: str) -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await store.create_account(
            session, tenant_id=tenant_id, type="checking", currency="USD", name="Main", now=_NOW
        )
        await session.commit()
    return account.account_id


@db_required
async def test_create_and_list_account_roundtrip(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        accounts = await store.list_accounts(session)

    assert [a.account_id for a in accounts] == [account_id]
    assert accounts[0].type == "checking"


@db_required
async def test_create_transaction_requires_existing_account(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(IntegrityError):
            await store.create_transaction(
                session,
                tenant_id=tenant_id,
                account_id="99999999-9999-4999-8999-999999999999",
                category="groceries",
                amount_minor_units=-1000,
                currency="USD",
                description="",
                merchant=None,
                occurred_at=_NOW,
                now=_NOW,
            )
    # account_id above is unused in this negative test's assertions but confirms the
    # fixture account exists so the FK failure is genuinely about the bad reference.
    assert account_id


@db_required
async def test_transaction_and_category_spend_roundtrip(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="groceries",
            amount_minor_units=-4200,
            currency="USD",
            description="Weekly shop",
            merchant="Acme Grocery",
            occurred_at=_NOW - timedelta(days=1),
            now=_NOW,
        )
        await store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="income",
            amount_minor_units=300_000,
            currency="USD",
            description="Paycheck",
            merchant=None,
            occurred_at=_NOW - timedelta(days=2),
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        txns = await store.list_transactions(session)
        spend = await store.get_category_spend(
            session, start=_NOW - timedelta(days=7), end=_NOW, currency="USD"
        )
        income, expense = await store.get_income_expense_totals(
            session, start=_NOW - timedelta(days=7), end=_NOW, currency="USD"
        )

    assert len(txns) == 2
    assert {s.category: s.spent_minor_units for s in spend} == {"groceries": 4200}
    assert income == 300_000
    assert expense == 4200


@db_required
async def test_list_transactions_filters_by_category_and_window(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="groceries",
            amount_minor_units=-1000,
            currency="USD",
            description="",
            merchant=None,
            occurred_at=_NOW - timedelta(days=1),
            now=_NOW,
        )
        await store.create_transaction(
            session,
            tenant_id=tenant_id,
            account_id=account_id,
            category="dining",
            amount_minor_units=-2000,
            currency="USD",
            description="",
            merchant=None,
            occurred_at=_NOW - timedelta(days=40),
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        recent_groceries = await store.list_transactions(
            session, category="groceries", start=_NOW - timedelta(days=7), end=_NOW
        )

    assert len(recent_groceries) == 1
    assert recent_groceries[0].category == "groceries"


@db_required
async def test_get_latest_budgets_returns_most_recent_per_category(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await store.create_budget(
            session,
            tenant_id=tenant_id,
            category="groceries",
            cap_minor_units=40_000,
            currency="USD",
            period="monthly",
            now=_NOW - timedelta(days=10),
        )
        await store.create_budget(
            session,
            tenant_id=tenant_id,
            category="groceries",
            cap_minor_units=50_000,
            currency="USD",
            period="monthly",
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        budgets = await store.get_latest_budgets(session)

    assert len(budgets) == 1
    assert budgets[0].cap_minor_units == 50_000  # the newer row wins


@db_required
async def test_cross_tenant_isolation(tenant_id, other_tenant_id) -> None:
    await _seed_account(tenant_id)

    async with get_tenant_session(other_tenant_id) as session:
        accounts = await store.list_accounts(session)

    assert accounts == []
