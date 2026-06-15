"""Concurrent insert test for the audit log hash chain (F-003).

Spawns multiple concurrent inserts into events_audit_log via separate DB
sessions and verifies that the chain remains valid after all inserts complete.

SQLAlchemy AsyncSession is NOT thread-safe or concurrent-coroutine-safe — each
concurrent insert must use its own session. This test opens N sessions, each
in a separate transaction, inserts one event per session, commits all of them,
and then validates the chain from a fresh read session.

The advisory lock (pg_advisory_xact_lock(_CHAIN_ADVISORY_LOCK_ID)) in
AuditLogRepository serializes the critical section (tip-fetch + insert) across
concurrent transactions at the Postgres level, preventing chain corruption.

Cleanup: after the test, we verify the chain and leave the committed rows.
Because these are real committed rows (not savepoint-isolated), we use a
separate cleanup step. Test isolation note: this test leaves rows in the DB.
Future runs accumulate rows but the chain always validates from the beginning.
"""

from __future__ import annotations

import asyncio
import os
import re
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from persistence.repositories.audit_log_repository import AuditLogRepository


def _uid() -> str:
    return str(uuid.uuid4())


def _usage_event(**overrides) -> dict:
    base = {
        "event_id": _uid(),
        "event_type": "usage",
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": "req-" + _uid()[:8],
        "tenant_id": _uid(),
        "team_id": _uid(),
        "project_id": _uid(),
        "agent_id": "gateway-core",
        "model": "gpt-4",
        "tokens_in": 100,
        "tokens_out": 200,
        "latency_ms": 350,
        "cost_estimate_cents": 0.05,
    }
    base.update(overrides)
    return base


def _get_async_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


async def _insert_one(url: str, event_data: dict) -> int:
    """Open a separate DB session, insert one event, commit, return sequence_number."""
    # server_settings sets app.session_kind='privileged' at connect time —
    # required for _assert_privileged_session's secondary defense-in-depth check.
    engine = create_async_engine(
        url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    try:
        async with factory() as sess:
            async with sess.begin():
                repo = AuditLogRepository(sess)
                row = await repo.append(event_data)
                seq = row.sequence_number
        return seq
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_inserts_do_not_corrupt_chain() -> None:
    """N concurrent inserts (each in own session) must produce a valid chain.

    Each coroutine opens a separate AsyncSession and commits independently.
    The advisory lock (_CHAIN_ADVISORY_LOCK_ID) in AuditLogRepository serializes
    the critical section (prev_hash fetch + insert) at the Postgres level,
    preventing chain forks.
    """
    url = _get_async_url()
    if not url:
        pytest.skip("DATABASE_URL not set")

    n_concurrent = 8
    events = [_usage_event() for _ in range(n_concurrent)]

    # Fire all inserts concurrently — each in its own session/transaction.
    tasks = [asyncio.create_task(_insert_one(url, ev)) for ev in events]
    sequence_numbers = await asyncio.gather(*tasks)

    assert len(sequence_numbers) == n_concurrent
    # All sequence numbers must be distinct (bigserial auto-increment).
    assert (
        len(set(sequence_numbers)) == n_concurrent
    ), f"Duplicate sequence numbers: {sequence_numbers}"

    # Validate the full chain from a fresh read session.
    engine = create_async_engine(
        url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    try:
        async with factory() as sess:
            async with sess.begin():
                repo = AuditLogRepository(sess)
                result = await repo.validate_chain()
    finally:
        await engine.dispose()

    assert result.is_valid is True, f"Chain invalid after concurrent inserts: {result.error_detail}"
    assert result.rows_checked >= n_concurrent
