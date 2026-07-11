"""D-024 service-layer DB tests: idempotent replay, daily-cap boundary, currency
mismatch, atomic ledger wiring, and the D-009 audit-chain rows — all against a real
Postgres (real RLS, real constraints), never stubbed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from delta.micro_transactions.schemas import (
    DAILY_CAP_MINOR_UNITS,
    ExecutionRequest,
)
from delta.micro_transactions.service import (
    AccountNotFoundError,
    execute_micro_transaction,
)
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_privileged_session, get_tenant_session
from delta.personal_finance.schemas import AccountCreateRequest
from delta.personal_finance.service import create_account

from .conftest import db_required


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _make_account(tenant_id: str, *, currency: str = "USD") -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await create_account(
            session,
            AccountCreateRequest(
                tenant_id=tenant_id, type="checking", currency=currency, name="Main"
            ),
            now=_now(),
        )
    return account.account_id


def _request(tenant_id: str, account_id: str, key: str, **overrides) -> ExecutionRequest:
    payload = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "idempotency_key": key,
        "amount_minor_units": 500,
        "currency": "USD",
        "category": "dining",
        "requested_by": "Jane",
    }
    payload.update(overrides)
    return ExecutionRequest(**payload)


@db_required
async def test_execute_returns_executed_with_ledger_txn(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await execute_micro_transaction(session, _request(tenant_id, account_id, "k-1"))
    assert view.status == "executed"
    assert view.rejection_reason is None
    assert view.txn_id is not None
    assert view.idempotent_replay is False


@db_required
async def test_executed_row_and_ledger_row_are_atomic(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        view = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "k-1", amount_minor_units=750)
        )

    from delta.personal_finance.store import list_transactions

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert len(txns) == 1
    assert txns[0].txn_id == view.txn_id
    # The engine's positive magnitude lands as a NEGATIVE (expense) ledger amount,
    # per D-021's signed convention, tagged with the execution source.
    assert txns[0].amount_minor_units == -750
    assert txns[0].source == "execution"


@db_required
async def test_replayed_key_returns_original_without_reexecuting(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    async with get_tenant_session(tenant_id) as session:
        first = await execute_micro_transaction(session, _request(tenant_id, account_id, "k-1"))
    async with get_tenant_session(tenant_id) as session:
        replay = await execute_micro_transaction(session, _request(tenant_id, account_id, "k-1"))

    assert replay.idempotent_replay is True
    assert replay.execution_id == first.execution_id
    assert replay.txn_id == first.txn_id

    from delta.personal_finance.store import list_transactions

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert len(txns) == 1  # nothing re-executed


@db_required
async def test_replayed_rejection_is_replayed_not_retried(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    async with get_tenant_session(tenant_id) as session:
        first = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "k-1", currency="EUR")
        )
    assert first.status == "rejected"

    async with get_tenant_session(tenant_id) as session:
        replay = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "k-1", currency="EUR")
        )
    assert replay.idempotent_replay is True
    assert replay.status == "rejected"
    assert replay.execution_id == first.execution_id


@db_required
async def test_currency_mismatch_records_rejection(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    async with get_tenant_session(tenant_id) as session:
        view = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "k-1", currency="EUR")
        )
    assert view.status == "rejected"
    assert view.rejection_reason == "currency_mismatch"
    assert view.txn_id is None

    from delta.personal_finance.store import list_transactions

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert txns == []  # no ledger row for a rejected attempt


@db_required
async def test_daily_cap_exceeded_records_rejection(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    # Fill the cap with max-size executions, then one more is rejected.
    per_txn = 10_000  # MAX_MICRO_TRANSACTION_MINOR_UNITS
    executions_to_fill = DAILY_CAP_MINOR_UNITS // per_txn
    for i in range(executions_to_fill):
        async with get_tenant_session(tenant_id) as session:
            view = await execute_micro_transaction(
                session,
                _request(tenant_id, account_id, f"fill-{i}", amount_minor_units=per_txn),
            )
        assert view.status == "executed"

    async with get_tenant_session(tenant_id) as session:
        over = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "over", amount_minor_units=1)
        )
    assert over.status == "rejected"
    assert over.rejection_reason == "daily_cap_exceeded"
    assert over.txn_id is None


@db_required
async def test_daily_cap_enforced_exactly_at_boundary(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    # Spend DAILY_CAP - 100, then exactly 100 more is ALLOWED (total == cap, not >),
    # then 1 more is rejected.
    async with get_tenant_session(tenant_id) as session:
        await execute_micro_transaction(
            session, _request(tenant_id, account_id, "k-1", amount_minor_units=10_000)
        )
    for i, amount in enumerate([10_000, 10_000, 10_000, 9_900]):
        async with get_tenant_session(tenant_id) as session:
            view = await execute_micro_transaction(
                session,
                _request(tenant_id, account_id, f"k-{i + 2}", amount_minor_units=amount),
            )
        assert view.status == "executed"

    async with get_tenant_session(tenant_id) as session:
        at_boundary = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "boundary", amount_minor_units=100)
        )
    assert at_boundary.status == "executed"  # total == cap exactly

    async with get_tenant_session(tenant_id) as session:
        over = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "over", amount_minor_units=1)
        )
    assert over.status == "rejected"
    assert over.rejection_reason == "daily_cap_exceeded"


@db_required
async def test_rejected_attempts_do_not_consume_cap(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    # A burst of currency-mismatch rejections must not reduce executable headroom.
    for i in range(5):
        async with get_tenant_session(tenant_id) as session:
            await execute_micro_transaction(
                session,
                _request(
                    tenant_id, account_id, f"bad-{i}", currency="EUR", amount_minor_units=10_000
                ),
            )
    async with get_tenant_session(tenant_id) as session:
        view = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "good", amount_minor_units=10_000)
        )
    assert view.status == "executed"


@db_required
async def test_unknown_account_raises_404_shape(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await execute_micro_transaction(
                session,
                _request(tenant_id, "99999999-9999-4999-8999-999999999999", "k-1"),
            )


@db_required
async def test_cross_tenant_account_is_404(tenant_id, other_tenant_id) -> None:
    victim_account = await _make_account(other_tenant_id)
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await execute_micro_transaction(session, _request(tenant_id, victim_account, "k-1"))


@db_required
async def test_execution_lands_in_d009_audit_chain(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    async with get_tenant_session(tenant_id) as session:
        executed = await execute_micro_transaction(session, _request(tenant_id, account_id, "k-1"))
    async with get_tenant_session(tenant_id) as session:
        rejected = await execute_micro_transaction(
            session, _request(tenant_id, account_id, "k-2", currency="EUR")
        )

    async with get_tenant_session(tenant_id) as session:
        executed_rows = await list_history(
            session, entity_type="micro_transaction", entity_id=executed.execution_id
        )
        rejected_rows = await list_history(
            session, entity_type="micro_transaction", entity_id=rejected.execution_id
        )
    assert {r.action for r in executed_rows} == {"executed"}
    assert {r.action for r in rejected_rows} == {"rejected"}
    assert rejected_rows[0].note == "currency_mismatch"


@db_required
async def test_executions_table_has_no_update_delete_grant() -> None:
    async with get_privileged_session() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'delta' "
                    "AND table_name = 'micro_transaction_executions' "
                    "AND grantee = 'delta_app'"
                )
            )
        ).all()
    assert {r[0] for r in rows} == {"SELECT", "INSERT"}
