"""Micro-transaction execution orchestration (D-024, ADR-0024).

``execute_micro_transaction`` is the whole feature: a synchronous accept/reject
decision with every safety property applied inside ONE database transaction —

1. **Idempotency** — a replayed ``idempotency_key`` returns the stored original
   result (executed OR rejected) without re-executing anything; the DB's
   ``UNIQUE (tenant_id, idempotency_key)`` is the race backstop.
2. **Per-account serialization** — ``pg_advisory_xact_lock`` on the account id
   makes the daily-cap read -> insert critical section atomic under concurrency
   (the D-018-audit TOCTOU lesson, designed out up front).
3. **Caps** — a per-transaction "micro" ceiling (schema-enforced) and a rolling
   24h cumulative executed-spend ceiling per account (checked here). A capped-out
   attempt is RECORDED as a rejected execution row, not just bounced — the trace
   is a security feature.
4. **Atomic bookkeeping** — an executed row + its D-021 ``personal_transactions``
   ledger row (``source='execution'``, negative amount per that package's sign
   convention) + a D-009 hash-chain audit row all commit or roll back together.

Honesty boundary (ADR-0024 Sec 1): "execution" is atomic bookkeeping over Delta's
OWN personal-finance ledger. No payment rail, card network, or bank connection
exists anywhere in this codebase — this engine moves no real money.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.audit_log import append_history
from ..personal_finance import store as personal_finance_store
from . import store
from .schemas import DAILY_CAP_MINOR_UNITS, ExecutionRequest, ExecutionView

_DAILY_WINDOW = timedelta(hours=24)


class AccountNotFoundError(LookupError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _execution_to_view(record: store.ExecutionRecord, *, replay: bool = False) -> ExecutionView:
    return ExecutionView(
        execution_id=record.execution_id,
        tenant_id=record.tenant_id,
        account_id=record.account_id,
        idempotency_key=record.idempotency_key,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,
        category=record.category,  # type: ignore[arg-type]
        merchant=record.merchant,
        description=record.description,
        status=record.status,  # type: ignore[arg-type]
        rejection_reason=record.rejection_reason,  # type: ignore[arg-type]
        txn_id=record.txn_id,
        requested_by=record.requested_by,
        executed_at=record.executed_at,
        idempotent_replay=replay,
    )


async def _record_rejection(
    session: AsyncSession, req: ExecutionRequest, *, reason: str, now: datetime
) -> store.ExecutionRecord:
    record = await store.create_execution(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        idempotency_key=req.idempotency_key,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        category=req.category,
        merchant=req.merchant,
        description=req.description,
        status="rejected",
        rejection_reason=reason,
        txn_id=None,
        requested_by=req.requested_by,
        executed_at=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="micro_transaction",
        entity_id=record.execution_id,
        action="rejected",
        actor=req.requested_by,
        now=now,
        note=reason,
    )
    return record


async def execute_micro_transaction(session: AsyncSession, req: ExecutionRequest) -> ExecutionView:
    # Idempotent replay: the stored original outcome, executed or rejected, is THE
    # result for this key — nothing is re-checked or re-executed. (RLS confines the
    # lookup to the caller's tenant, so one tenant can never replay another's key.)
    existing = await store.get_by_idempotency_key(session, idempotency_key=req.idempotency_key)
    if existing is not None:
        return _execution_to_view(existing, replay=True)

    account = await personal_finance_store.get_account(session, account_id=req.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        # Mirrors D-021's own create_transaction 404 behavior — an unknown account
        # is a caller error (404), not a recordable execution attempt (there is no
        # account row to attribute the rejection to; the FK would reject it anyway).
        raise AccountNotFoundError(req.account_id)

    now = _now()

    # Serialize the cap check -> insert critical section for this account.
    await store.acquire_account_execution_lock(session, account_id=req.account_id)

    if req.currency != account.currency:
        record = await _record_rejection(session, req, reason="currency_mismatch", now=now)
        await session.commit()
        return _execution_to_view(record)

    executed_last_24h = await store.executed_total_since(
        session, account_id=req.account_id, since=now - _DAILY_WINDOW
    )
    if executed_last_24h + req.amount_minor_units > DAILY_CAP_MINOR_UNITS:
        record = await _record_rejection(session, req, reason="daily_cap_exceeded", now=now)
        await session.commit()
        return _execution_to_view(record)

    # Accepted: write the D-021 ledger row (negative amount = expense, per that
    # package's signed convention) + the execution row + the audit row atomically.
    txn = await personal_finance_store.create_transaction(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        category=req.category,
        amount_minor_units=-req.amount_minor_units,
        currency=req.currency,
        description=req.description,
        merchant=req.merchant,
        occurred_at=now,
        now=now,
        source="execution",
    )
    record = await store.create_execution(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        idempotency_key=req.idempotency_key,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        category=req.category,
        merchant=req.merchant,
        description=req.description,
        status="executed",
        rejection_reason=None,
        txn_id=txn.txn_id,
        requested_by=req.requested_by,
        executed_at=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="micro_transaction",
        entity_id=record.execution_id,
        action="executed",
        actor=req.requested_by,
        now=now,
    )
    await session.commit()
    return _execution_to_view(record)


async def list_execution_views(
    session: AsyncSession,
    *,
    account_id: str | None,
    status: str | None,
    limit: int,
) -> list[ExecutionView]:
    records = await store.list_executions(
        session, account_id=account_id, status=status, limit=limit
    )
    return [_execution_to_view(r) for r in records]
