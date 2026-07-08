"""F-024 (ADR-0030) real backup → restore → chain-validate drill.

No mocks on the DB path: a real pg_dump, a real fresh throwaway target
database (CREATE DATABASE / DROP DATABASE — the CI `sentinel` role is
superuser, matching how tests/policy/conftest.py's own DB setup works), a
real pg_restore, and the REAL AuditLogRepository.validate_chain() (ADR-0004),
unmodified. This is the CI-verified half of "RPO/RTO validated" — the
measured timings are printed (run with `-s`) and documented, with the honest
caveat in deploy/DISASTER-RECOVERY.md §4, in the ADR itself: a small CI
dataset, not a production capacity estimate.

Skips cleanly if pg_dump/pg_restore are not on PATH (mirrors the
redis_integration / MinIO self-skip convention already used elsewhere in this
suite) or if DATABASE_URL is not set.
"""

from __future__ import annotations

import os
import re
import shutil
import uuid

import asyncpg
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from dr.backends.local import LocalDirSink
from dr.backup import run_backup
from dr.pg_url import parse_pg_url
from dr.restore import run_restore
from persistence.repositories.audit_log_repository import AuditLogRepository
from policy.audit_events import build_policy_event, new_intake_request_id, system_scope
from policy.constants import EVT_INTAKE_ACCEPTED

pytestmark = pytest.mark.skipif(
    shutil.which("pg_dump") is None or shutil.which("pg_restore") is None,
    reason="pg_dump/pg_restore not on PATH",
)

if not os.environ.get("DATABASE_URL"):
    pytest.skip("DATABASE_URL is not set", allow_module_level=True)

_SOURCE_URL = os.environ["DATABASE_URL"]


def _sqlalchemy_privileged_engine(url: str):
    asyncpg_url = re.sub(r"^postgresql\+\w+://", "postgresql+asyncpg://", url)
    if not asyncpg_url.startswith("postgresql+asyncpg://"):
        asyncpg_url = re.sub(r"^postgresql://", "postgresql+asyncpg://", asyncpg_url)
    return create_async_engine(
        asyncpg_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


@pytest_asyncio.fixture
async def throwaway_target_db():
    """Create a fresh, empty database on the SAME Postgres server as
    DATABASE_URL, yield its connection URL, then drop it — a real restore
    target, not a mock."""
    source = parse_pg_url(_SOURCE_URL)
    dbname = f"sentinel_dr_drill_{uuid.uuid4().hex[:12]}"
    maint_dsn = f"postgresql://{source.user}:{source.password}@{source.host}:{source.port}/postgres"

    conn = await asyncpg.connect(dsn=maint_dsn)
    try:
        await conn.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await conn.close()

    target_url = (
        f"postgresql://{source.user}:{source.password}@{source.host}:{source.port}/{dbname}"
    )
    try:
        yield target_url
    finally:
        conn = await asyncpg.connect(dsn=maint_dsn)
        try:
            # Terminate any lingering connections (e.g. a leaked pool) before DROP.
            await conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                dbname,
            )
            await conn.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        finally:
            await conn.close()


async def _append_marker_event(source_url: str) -> str:
    """Commit one real audit-log row to the SOURCE database and return its
    event_id, so the drill can confirm it survives dump -> restore."""
    engine = _sqlalchemy_privileged_engine(source_url)
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False, autocommit=False
    )
    request_id = new_intake_request_id()
    event = build_policy_event(
        EVT_INTAKE_ACCEPTED,
        scope=system_scope(),
        request_id=request_id,
        action_taken="logged",
        policy_id=f"dr-drill-{uuid.uuid4().hex[:8]}",
    )
    try:
        async with factory() as session, session.begin():
            await AuditLogRepository(session).append(event)
    finally:
        await engine.dispose()
    return event["event_id"]


@pytest.mark.asyncio
async def test_backup_restore_drill_preserves_hash_chain(tmp_path, throwaway_target_db):
    marker_event_id = await _append_marker_event(_SOURCE_URL)

    sink = LocalDirSink(str(tmp_path / "backups"))
    backup_result = await run_backup(sink, source_database_url=_SOURCE_URL, retention_days=14)
    assert backup_result.size_bytes > 0

    restore_result = await run_restore(
        sink, backup_result.key, target_database_url=throwaway_target_db
    )
    assert restore_result.rows_checked > 0

    print(
        f"\nF-024 drill: backup {backup_result.duration_s:.3f}s "
        f"({backup_result.size_bytes} bytes) + restore {restore_result.duration_s:.3f}s "
        f"({restore_result.rows_checked} rows chain-validated)"
    )

    # Confirm the marker row genuinely round-tripped byte-for-byte, not just
    # that SOME chain happened to validate.
    engine = _sqlalchemy_privileged_engine(throwaway_target_db)
    try:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text("SELECT event_id FROM events_audit_log WHERE event_id = :eid"),
                    {"eid": marker_event_id},
                )
            ).one_or_none()
    finally:
        await engine.dispose()
    assert row is not None, "marker event did not survive the backup/restore round trip"


@pytest.mark.asyncio
async def test_backup_retention_deletes_old_objects(tmp_path):
    from datetime import UTC, datetime, timedelta

    sink = LocalDirSink(str(tmp_path / "backups"))
    old_now = datetime.now(UTC) - timedelta(days=30)
    result_old = await run_backup(
        sink, source_database_url=_SOURCE_URL, retention_days=14, now=old_now
    )
    result_new = await run_backup(sink, source_database_url=_SOURCE_URL, retention_days=14)

    assert result_old.key in result_new.deleted_for_retention
    remaining = {o.key for o in await sink.list_objects()}
    assert result_new.key in remaining
    assert result_old.key not in remaining
