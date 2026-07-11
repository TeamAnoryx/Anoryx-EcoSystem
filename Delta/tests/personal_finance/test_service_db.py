"""D-021 service-layer DB tests: account/transaction/budget lifecycle + the
financial-health-score composition.

Each mutating service call opens its OWN `get_tenant_session` block and commits
before the next call reads/writes — reusing one session across two commits clears
the transaction-local RLS GUC after the first commit, so the second call's read
silently sees zero rows (this exact bug class was hit and fixed while writing these
tests; see ``tests/executive/conftest.py``'s identical documented precedent).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.persistence.database import get_tenant_session
from delta.personal_finance.schemas import (
    AccountCreateRequest,
    BudgetCreateRequest,
    FinancialHealthQuery,
    TransactionCreateRequest,
)
from delta.personal_finance.service import (
    AccountNotFoundError,
    create_account,
    create_budget,
    create_transaction,
    get_financial_health,
)

from .conftest import db_required

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


async def _seed_account(tenant_id: str) -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await create_account(
            session,
            AccountCreateRequest(tenant_id=tenant_id, type="checking", currency="USD", name="Main"),
            now=_NOW,
        )
    return account.account_id


@db_required
async def test_create_account_and_transaction_roundtrip(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        txn = await create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                category="groceries",
                amount_minor_units=-4200,
                currency="USD",
                occurred_at=_NOW,
            ),
            now=_NOW,
        )

    assert txn.account_id == account_id
    assert txn.amount_minor_units == -4200


@db_required
async def test_create_transaction_against_unknown_account_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        try:
            await create_transaction(
                session,
                TransactionCreateRequest(
                    tenant_id=tenant_id,
                    account_id="99999999-9999-4999-8999-999999999999",
                    category="groceries",
                    amount_minor_units=-4200,
                    currency="USD",
                    occurred_at=_NOW,
                ),
                now=_NOW,
            )
            raised = False
        except AccountNotFoundError:
            raised = True
    assert raised


@db_required
async def test_create_transaction_against_other_tenants_account_raises(
    tenant_id, other_tenant_id
) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(other_tenant_id) as session:
        try:
            await create_transaction(
                session,
                TransactionCreateRequest(
                    tenant_id=other_tenant_id,
                    account_id=account_id,
                    category="groceries",
                    amount_minor_units=-100,
                    currency="USD",
                    occurred_at=_NOW,
                ),
                now=_NOW,
            )
            raised = False
        except AccountNotFoundError:
            raised = True
    assert raised


@db_required
async def test_financial_health_composes_savings_and_budget_adherence(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                category="income",
                amount_minor_units=200_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=1),
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        await create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                category="groceries",
                amount_minor_units=-40_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=1),
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        await create_budget(
            session,
            BudgetCreateRequest(
                tenant_id=tenant_id, category="groceries", cap_minor_units=50_000, currency="USD"
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        health = await get_financial_health(
            session,
            FinancialHealthQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=7), end=_NOW),
            now=_NOW,
            currency="USD",
        )

    assert health.total_income_minor_units == 200_000
    assert health.total_expense_minor_units == 40_000
    assert health.savings_rate == 0.8
    assert len(health.budgets) == 1
    assert health.budgets[0].over_cap is False
    # savings_points = round((0.8+1)/2*60) = 54; budget_points = round(1/1*40) = 40
    assert health.health_score == 94


@db_required
async def test_financial_health_zero_state_scores_zero(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        health = await get_financial_health(
            session,
            FinancialHealthQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=7), end=_NOW),
            now=_NOW,
            currency="USD",
        )

    assert health.total_income_minor_units == 0
    assert health.savings_rate is None
    assert health.budgets == []
    assert health.health_score == 0


@db_required
async def test_financial_health_flags_over_cap_budget(tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                category="dining",
                amount_minor_units=-15_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=1),
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        await create_budget(
            session,
            BudgetCreateRequest(
                tenant_id=tenant_id, category="dining", cap_minor_units=10_000, currency="USD"
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        health = await get_financial_health(
            session,
            FinancialHealthQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=7), end=_NOW),
            now=_NOW,
            currency="USD",
        )

    assert health.budgets[0].over_cap is True
    assert health.budgets[0].spent_minor_units == 15_000


@db_required
async def test_financial_health_excludes_non_report_currency_budget(tenant_id) -> None:
    # Security audit finding: a budget capped in a different currency than the
    # report's spend figures must be EXCLUDED from the adherence calculation — it
    # must never be silently scored as within-cap against a USD-scoped spend of 0.
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                category="dining",
                amount_minor_units=-500_000,
                currency="EUR",
                occurred_at=_NOW - timedelta(days=1),
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        await create_budget(
            session,
            BudgetCreateRequest(
                tenant_id=tenant_id, category="dining", cap_minor_units=10_000, currency="EUR"
            ),
            now=_NOW,
        )

    async with get_tenant_session(tenant_id) as session:
        health = await get_financial_health(
            session,
            FinancialHealthQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=7), end=_NOW),
            now=_NOW,
            currency="USD",
        )

    # The massively-overspent EUR budget must not appear as a within-cap USD budget,
    # and must not contribute a perfect 40/40 budget-adherence score.
    assert health.budgets == []
    assert health.health_score == 0


@db_required
async def test_financial_health_cross_tenant_isolated(tenant_id, other_tenant_id) -> None:
    account_id = await _seed_account(tenant_id)

    async with get_tenant_session(tenant_id) as session:
        await create_transaction(
            session,
            TransactionCreateRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                category="income",
                amount_minor_units=100_000,
                currency="USD",
                occurred_at=_NOW - timedelta(days=1),
            ),
            now=_NOW,
        )

    async with get_tenant_session(other_tenant_id) as session:
        health = await get_financial_health(
            session,
            FinancialHealthQuery(
                tenant_id=other_tenant_id, start=_NOW - timedelta(days=7), end=_NOW
            ),
            now=_NOW,
            currency="USD",
        )

    assert health.total_income_minor_units == 0
