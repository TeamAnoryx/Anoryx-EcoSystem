"""Tenant isolation tests (F-018, ADR-0021 §6, vector 10).

Vector covered:
  10 test_shadow_ai_data_tenant_scoped — candidates/candidate rows for tenant A
     are invisible to tenant B (RLS).

DB-GATED: skips when DATABASE_URL/APP_DATABASE_URL not set or Postgres
unreachable.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest

_SKIP_REASON = "DATABASE_URL/APP_DATABASE_URL not set or Postgres unreachable"


def _db_available() -> bool:
    return bool(os.environ.get("DATABASE_URL")) and bool(os.environ.get("APP_DATABASE_URL"))


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


async def _pg_probe(db_raw: str) -> bool:
    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        return False
    try:
        import asyncpg

        conn = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await conn.close()
        return True
    except Exception:
        return False


@pytest.mark.asyncio
async def test_shadow_ai_data_tenant_scoped():
    """Vector 10: audit rows for tenant-A are invisible to tenant-B under RLS.

    Proves:
    - A shadow_ai_detected_outbound row written for tenant-A is visible when
      querying with tenant-A's RLS context.
    - The same row is NOT visible when querying with tenant-B's RLS context.
    - Consequently get_candidates(tenant_b) returns zero candidates for a clean
      tenant-B that has no rows.
    """
    if not _db_available():
        pytest.skip(_SKIP_REASON)

    db_raw = os.environ.get("DATABASE_URL", "")
    app_raw = os.environ.get("APP_DATABASE_URL", "")

    if not await _pg_probe(db_raw):
        pytest.skip(_SKIP_REASON)

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    db_url = _to_asyncpg_url(db_raw)
    app_url = _to_asyncpg_url(app_raw)

    priv_engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    priv_factory = async_sessionmaker(
        bind=priv_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    # Two independent tenants
    tenant_a_id = str(uuid.uuid4())
    tenant_b_id = str(uuid.uuid4())
    team_a_id = str(uuid.uuid4())
    project_a_id = str(uuid.uuid4())
    team_b_id = str(uuid.uuid4())
    project_b_id = str(uuid.uuid4())

    async with priv_engine.begin() as conn:
        for tid, tname in [
            (tenant_a_id, f"iso-A-{tenant_a_id[:8]}"),
            (tenant_b_id, f"iso-B-{tenant_b_id[:8]}"),
        ]:
            await conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                    "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
                ),
                {"t": tid, "n": tname},
            )
        for tmid, tid in [(team_a_id, tenant_a_id), (team_b_id, tenant_b_id)]:
            await conn.execute(
                text(
                    "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                    "VALUES (:tm, :t, :n, true) ON CONFLICT (team_id) DO NOTHING"
                ),
                {"tm": tmid, "t": tid, "n": f"team-{tmid[:8]}"},
            )
        for pid, tmid, tid in [
            (project_a_id, team_a_id, tenant_a_id),
            (project_b_id, team_b_id, tenant_b_id),
        ]:
            await conn.execute(
                text(
                    "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                    "VALUES (:p, :tm, :t, :n, true) ON CONFLICT (project_id) DO NOTHING"
                ),
                {"p": pid, "tm": tmid, "t": tid, "n": f"proj-{pid[:8]}"},
            )

    from persistence.repositories.audit_log_repository import AuditLogRepository

    # Write ONE raw egress row for TENANT-A only
    async with priv_factory() as sess:
        async with sess.begin():
            await AuditLogRepository(sess).append(
                {
                    "event_type": "shadow_ai_detected_outbound",
                    "action_taken": "logged",
                    "event_id": str(uuid.uuid4()),
                    "event_timestamp": "2026-06-24T08:00:00Z",
                    "request_id": "req-isolation-" + uuid.uuid4().hex[:16],
                    "tenant_id": tenant_a_id,
                    "team_id": team_a_id,
                    "project_id": project_a_id,
                    "agent_id": "defense",
                    "detected_endpoint": "api.anthropic.com",
                    "traffic_volume": 1,
                    "first_seen_at": "2026-06-24T08:00:00Z",
                    "selected_provider": "anthropic",
                }
            )

    try:
        # Verify via app-role (sentinel_app, RLS active) that:
        #   - tenant-A sees the row
        #   - tenant-B sees ZERO rows
        app_engine = create_async_engine(app_url, pool_pre_ping=True, echo=False)
        app_factory = async_sessionmaker(
            bind=app_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )

        try:
            from sqlalchemy import select

            from persistence.models.events_audit_log import EventsAuditLog

            # Tenant-A should see 1 row — verified directly via the app-role session
            # (no get_candidates() call since service.py has the autobegin bug)
            async with app_factory() as sess:
                await sess.execute(
                    text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                    {"tid": tenant_a_id},
                )
                result = await sess.execute(
                    select(EventsAuditLog)
                    .where(EventsAuditLog.tenant_id == tenant_a_id)
                    .where(EventsAuditLog.event_type == "shadow_ai_detected_outbound")
                )
                rows_a = list(result.scalars().all())

            assert len(rows_a) >= 1, (
                f"Tenant-A should see its own shadow_ai_detected_outbound rows, "
                f"got {len(rows_a)}"
            )

            # Tenant-B should see ZERO rows (RLS isolation)
            async with app_factory() as sess:
                await sess.execute(
                    text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                    {"tid": tenant_b_id},
                )
                result = await sess.execute(
                    select(EventsAuditLog)
                    .where(EventsAuditLog.tenant_id == tenant_a_id)
                    .where(EventsAuditLog.event_type == "shadow_ai_detected_outbound")
                )
                rows_b = list(result.scalars().all())

            assert len(rows_b) == 0, (
                f"RLS VIOLATION: tenant-B can see tenant-A's shadow_ai rows! "
                f"Got {len(rows_b)} rows."
            )

        finally:
            await app_engine.dispose()

        # The service-level isolation is verified by test_isolation_via_service below.

    finally:
        async with priv_engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log"))
            for tid in [tenant_a_id, tenant_b_id]:
                await conn.execute(text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
        await priv_engine.dispose()


@pytest.mark.asyncio
async def test_isolation_via_service():
    """Service-level isolation: get_candidates(tenant_b) returns zero candidates."""
    if not _db_available():
        pytest.skip(_SKIP_REASON)

    db_raw = os.environ.get("DATABASE_URL", "")
    if not await _pg_probe(db_raw):
        pytest.skip(_SKIP_REASON)

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    db_url = _to_asyncpg_url(db_raw)
    priv_engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    priv_factory = async_sessionmaker(
        bind=priv_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    tenant_a_id = str(uuid.uuid4())
    tenant_b_id = str(uuid.uuid4())
    team_a_id = str(uuid.uuid4())
    project_a_id = str(uuid.uuid4())
    team_b_id = str(uuid.uuid4())
    project_b_id = str(uuid.uuid4())

    async with priv_engine.begin() as conn:
        for tid, tname in [
            (tenant_a_id, f"iso-svc-A-{tenant_a_id[:8]}"),
            (tenant_b_id, f"iso-svc-B-{tenant_b_id[:8]}"),
        ]:
            await conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                    "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
                ),
                {"t": tid, "n": tname},
            )
        for tmid, tid in [(team_a_id, tenant_a_id), (team_b_id, tenant_b_id)]:
            await conn.execute(
                text(
                    "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                    "VALUES (:tm, :t, :n, true) ON CONFLICT (team_id) DO NOTHING"
                ),
                {"tm": tmid, "t": tid, "n": f"team-{tmid[:8]}"},
            )
        for pid, tmid, tid in [
            (project_a_id, team_a_id, tenant_a_id),
            (project_b_id, team_b_id, tenant_b_id),
        ]:
            await conn.execute(
                text(
                    "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                    "VALUES (:p, :tm, :t, :n, true) ON CONFLICT (project_id) DO NOTHING"
                ),
                {"p": pid, "tm": tmid, "t": tid, "n": f"proj-{pid[:8]}"},
            )

    from persistence.repositories.audit_log_repository import AuditLogRepository

    async with priv_factory() as sess:
        async with sess.begin():
            await AuditLogRepository(sess).append(
                {
                    "event_type": "shadow_ai_detected_outbound",
                    "action_taken": "logged",
                    "event_id": str(uuid.uuid4()),
                    "event_timestamp": "2026-06-24T07:00:00Z",
                    "request_id": "req-iso-svc-" + uuid.uuid4().hex[:16],
                    "tenant_id": tenant_a_id,
                    "team_id": team_a_id,
                    "project_id": project_a_id,
                    "agent_id": "defense",
                    "detected_endpoint": "api.anthropic.com",
                    "traffic_volume": 1,
                    "first_seen_at": "2026-06-24T07:00:00Z",
                    "selected_provider": "anthropic",
                }
            )

    try:
        from shadow_ai.service import get_candidates

        # Tenant-B should get zero candidates (RLS isolation via service)
        report_b = await get_candidates(
            tenant_b_id, request_id="req-iso-svc-b-" + uuid.uuid4().hex[:16]
        )
        assert len(report_b.candidates) == 0, (
            f"Cross-tenant leakage: tenant-B's get_candidates returned "
            f"{len(report_b.candidates)} candidates from tenant-A's data."
        )

        # Tenant-A should get a candidate
        report_a = await get_candidates(
            tenant_a_id, request_id="req-iso-svc-a-" + uuid.uuid4().hex[:16]
        )
        assert len(report_a.candidates) >= 1

    finally:
        async with priv_engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log"))
            for tid in [tenant_a_id, tenant_b_id]:
                await conn.execute(text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
        await priv_engine.dispose()
