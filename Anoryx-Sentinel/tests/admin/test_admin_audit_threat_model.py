"""Admin audit-log read — threat model vectors 9, 10, 11 (ADR-0014 §6/§11).

DB-backed.

  9   test_admin_audit_read_appends_one_access_event — the serving read writes
      ZERO rows; the operation appends exactly ONE admin_audit_accessed event
      (the D8 R1<->R5 reconciliation).
  10  test_admin_audit_read_tenant_scoped — operator read of tenant A returns
      only A's events; test_tenant_self_audit_read — a tenant Bearer reads only
      its own events (RLS), and the self read writes zero rows.
  11  test_admin_audit_read_reports_chain_status — chain_verified is reported
      honestly (True over an intact chain), with rows_checked > 0.

Skips when no DB is configured.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from admin.audit import emit_admin_event
from persistence.models.events_audit_log import EventsAuditLog

pytestmark = pytest.mark.asyncio


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


async def _seed_tenant_with_events(n: int) -> str:
    """Commit a tenant + n admin_tenant_created audit events. Returns tenant_id."""
    engine = _priv_engine()
    tid = str(uuid.uuid4())
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as s:
            async with s.begin():
                await s.execute(
                    text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                    {"t": tid, "n": f"at-{tid[:8]}"},
                )
                for i in range(n):
                    await emit_admin_event(
                        s,
                        event_type="admin_tenant_created",
                        target_tenant_id=tid,
                        request_id=f"req-seed-{i:02d}",
                    )
    finally:
        await engine.dispose()
    return tid


async def _seed_scope() -> tuple[str, str, str]:
    """Commit a tenant + team + project (for key minting). Returns ids."""
    engine = _priv_engine()
    tid, team, proj = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"at-{tid[:8]}"},
            )
            await conn.execute(
                text(
                    "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                    "VALUES (:tm, :t, :n, true)"
                ),
                {"tm": team, "t": tid, "n": f"team-{team[:8]}"},
            )
            await conn.execute(
                text(
                    "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                    "VALUES (:p, :tm, :t, :n, true)"
                ),
                {"p": proj, "tm": team, "t": tid, "n": f"proj-{proj[:8]}"},
            )
    finally:
        await engine.dispose()
    return tid, team, proj


async def _count_events(session, tenant_id: str) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(EventsAuditLog)
                .where(EventsAuditLog.tenant_id == tenant_id)
            )
        ).scalar_one()
    )


async def test_admin_audit_read_tenant_scoped(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Vector 10 (admin): operator read of tenant A returns ONLY A's events."""
    tid_a = await _seed_tenant_with_events(3)
    tid_b = await _seed_tenant_with_events(2)
    async with _client(admin_app) as client:
        ra = await client.get(f"/admin/tenants/{tid_a}/audit", headers=admin_auth_headers)
        assert ra.status_code == 200, ra.text
        ev_a = ra.json()["events"]
        assert ev_a and all(e["tenant_id"] == tid_a for e in ev_a)

        rb = await client.get(f"/admin/tenants/{tid_b}/audit", headers=admin_auth_headers)
        assert all(e["tenant_id"] == tid_b for e in rb.json()["events"])
        # A's tenant id never appears in B's page.
        assert tid_a not in {e["tenant_id"] for e in rb.json()["events"]}


async def test_admin_audit_read_reports_chain_status(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Vector 11: the read API reports the F-003 chain verification status honestly."""
    tid = await _seed_tenant_with_events(2)
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{tid}/audit", headers=admin_auth_headers)
        body = r.json()
        assert body["chain_verified"] is True
        assert body["chain_rows_checked"] >= 2


async def test_admin_audit_read_appends_one_access_event(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Vector 9 / D8: serving read writes zero rows; the op appends exactly one
    admin_audit_accessed event."""
    tid = await _seed_tenant_with_events(2)
    before = await _count_events(session, tid)
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{tid}/audit", headers=admin_auth_headers)
        assert r.status_code == 200
    after = await _count_events(session, tid)
    assert after == before + 1  # ONLY the deliberate access event, nothing from the read

    newest = (
        await session.execute(
            select(EventsAuditLog)
            .where(EventsAuditLog.tenant_id == tid)
            .order_by(EventsAuditLog.sequence_number.desc())
            .limit(1)
        )
    ).scalar_one()
    assert newest.event_type == "admin_audit_accessed"


async def test_tenant_self_audit_read(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Vector 10 (tenant) + R5: a tenant Bearer reads only its own events; the
    self read writes zero rows (no admin access event)."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        # Mint a key for this tenant (emits admin_key_minted -> 1 event for tid).
        rm = await client.post(
            f"/admin/tenants/{tid}/keys",
            json={"team_id": team, "project_id": proj, "agent_id": "gateway-core"},
            headers=admin_auth_headers,
        )
        secret = rm.json()["secret"]

        before = await _count_events(session, tid)
        headers = {
            "Authorization": f"Bearer {secret}",
            "x-anoryx-tenant-id": tid,
            "x-anoryx-team-id": team,
            "x-anoryx-project-id": proj,
            "x-anoryx-agent-id": "gateway-core",
        }
        r = await client.get("/v1/audit", headers=headers)
        assert r.status_code == 200, r.text
        events = r.json()["events"]
        assert all(e["tenant_id"] == tid for e in events)
        assert r.json()["chain_verified"] is True

    # R5: the audit-read SERVING query writes zero rows. The only new row is the
    # gateway's universal terminal `usage` audit (emitted for EVERY /v1 request by
    # TerminalAuditMiddleware, orthogonal to the read path) — NOT an audit-read
    # write and NOT an admin access event (a self read never emits admin_audit_accessed).
    rows_after = (
        (
            await session.execute(
                select(EventsAuditLog)
                .where(EventsAuditLog.tenant_id == tid)
                .order_by(EventsAuditLog.sequence_number)
            )
        )
        .scalars()
        .all()
    )
    after = len(rows_after)
    assert after == before + 1
    assert rows_after[-1].event_type == "usage"  # the lone new row is the terminal log
    assert "admin_audit_accessed" not in {r.event_type for r in rows_after}
