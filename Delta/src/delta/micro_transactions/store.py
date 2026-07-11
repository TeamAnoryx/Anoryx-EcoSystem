"""Micro-transaction execution persistence (D-024, ADR-0024).

Tenant-scoped reads/writes against ``micro_transaction_executions`` (migration 0016).
Every function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like every prior Delta store module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import micro_transaction_executions

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class ExecutionRecord:
    execution_id: str
    tenant_id: str
    account_id: str
    idempotency_key: str
    amount_minor_units: int
    currency: str
    category: str
    merchant: str | None
    description: str
    status: str
    rejection_reason: str | None
    txn_id: str | None
    requested_by: str
    executed_at: datetime


def _execution_from_row(row) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=row.execution_id,
        tenant_id=row.tenant_id,
        account_id=row.account_id,
        idempotency_key=row.idempotency_key,
        amount_minor_units=row.amount_minor_units,
        currency=row.currency,
        category=row.category,
        merchant=row.merchant,
        description=row.description,
        status=row.status,
        rejection_reason=row.rejection_reason,
        txn_id=row.txn_id,
        requested_by=row.requested_by,
        executed_at=row.executed_at,
    )


async def acquire_account_execution_lock(session: AsyncSession, *, account_id: str) -> None:
    """Transaction-scoped advisory lock serializing the daily-cap read -> insert
    critical section for ONE account (auto-released at commit/rollback) — the same
    ``pg_advisory_xact_lock(hashtext(...))`` shape D-009's audit chain uses per
    tenant, scoped down to one account per lock key. Without this, two concurrent
    executions could both read a within-cap daily total and both commit, jointly
    exceeding the cap (a classic TOCTOU race — D-018's audit caught exactly this
    class of bug in invoice over-commitment; here it is designed out up front).
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:a))"), {"a": account_id})


async def get_by_idempotency_key(
    session: AsyncSession, *, idempotency_key: str
) -> ExecutionRecord | None:
    row = (
        await session.execute(
            select(micro_transaction_executions).where(
                micro_transaction_executions.c.idempotency_key == idempotency_key
            )
        )
    ).first()
    return None if row is None else _execution_from_row(row)


async def executed_total_since(session: AsyncSession, *, account_id: str, since: datetime) -> int:
    """Sum of EXECUTED (never rejected) magnitudes for ``account_id`` with
    ``executed_at >= since`` — the rolling daily-cap accumulator."""
    stmt = select(
        func.coalesce(func.sum(micro_transaction_executions.c.amount_minor_units), 0)
    ).where(
        micro_transaction_executions.c.account_id == account_id,
        micro_transaction_executions.c.status == "executed",
        micro_transaction_executions.c.executed_at >= since,
    )
    return int((await session.execute(stmt)).scalar_one())


async def create_execution(
    session: AsyncSession,
    *,
    tenant_id: str,
    account_id: str,
    idempotency_key: str,
    amount_minor_units: int,
    currency: str,
    category: str,
    merchant: str | None,
    description: str,
    status: str,
    rejection_reason: str | None,
    txn_id: str | None,
    requested_by: str,
    executed_at: datetime,
    execution_id: str | None = None,
) -> ExecutionRecord:
    eid = execution_id or str(uuid.uuid4())
    await session.execute(
        insert(micro_transaction_executions).values(
            execution_id=eid,
            tenant_id=tenant_id,
            account_id=account_id,
            idempotency_key=idempotency_key,
            amount_minor_units=amount_minor_units,
            currency=currency,
            category=category,
            merchant=merchant,
            description=description,
            status=status,
            rejection_reason=rejection_reason,
            txn_id=txn_id,
            requested_by=requested_by,
            executed_at=executed_at,
        )
    )
    return ExecutionRecord(
        execution_id=eid,
        tenant_id=tenant_id,
        account_id=account_id,
        idempotency_key=idempotency_key,
        amount_minor_units=amount_minor_units,
        currency=currency,
        category=category,
        merchant=merchant,
        description=description,
        status=status,
        rejection_reason=rejection_reason,
        txn_id=txn_id,
        requested_by=requested_by,
        executed_at=executed_at,
    )


async def list_executions(
    session: AsyncSession,
    *,
    account_id: str | None = None,
    status: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[ExecutionRecord]:
    stmt = select(micro_transaction_executions)
    if account_id is not None:
        stmt = stmt.where(micro_transaction_executions.c.account_id == account_id)
    if status is not None:
        stmt = stmt.where(micro_transaction_executions.c.status == status)
    stmt = stmt.order_by(micro_transaction_executions.c.executed_at.desc()).limit(
        _clamp_limit(limit)
    )
    rows = (await session.execute(stmt)).all()
    return [_execution_from_row(r) for r in rows]
