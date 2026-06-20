"""Admin virtual-key management — threat model vectors 6, 7, 8 (ADR-0014 §5/§11).

DB-backed. Each test seeds a committed tenant+team+project (FKs for key minting)
via a privileged connection, then drives the real /admin/tenants/{id}/keys routes.

  6  test_key_secret_returned_once — mint returns the secret once; list never
     returns the secret or the fingerprint.
  7  test_revoked_key_rejected — after revoke, the gateway lookup denies the key.
  8  test_key_scoped_to_tenant — a key minted for tenant A is bound to A.
  +  test_rotate_immediate_revoke — rotation kills the old key instantly, the new
     key works, and admin_key_minted/_revoked carry the key's REAL team/project.

Skips when no DB is configured. admin_app / admin_auth_headers come from conftest.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.auth import ADMIN_PRINCIPAL
from persistence.models.events_audit_log import EventsAuditLog
from persistence.repositories.virtual_api_key_repository import (
    VirtualApiKeyAuthError,
    VirtualApiKeyRepository,
)

pytestmark = pytest.mark.asyncio


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


async def _seed_scope() -> tuple[str, str, str]:
    """Commit a tenant + team + project (FK prerequisites for key mint). Returns ids."""
    url = _to_asyncpg(os.environ["DATABASE_URL"])
    engine = create_async_engine(
        url, connect_args={"server_settings": {"app.session_kind": "privileged"}}
    )
    tid, team, proj = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"kt-{tid[:8]}"},
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


def _mint_body(team: str, proj: str) -> dict:
    return {"team_id": team, "project_id": proj, "agent_id": "gateway-core"}


async def test_key_secret_returned_once(admin_app, admin_auth_headers, truncate_audit_log_after):
    """Vector 6: secret is returned at mint only; list exposes neither secret nor fingerprint."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        rm = await client.post(
            f"/admin/tenants/{tid}/keys", json=_mint_body(team, proj), headers=admin_auth_headers
        )
        assert rm.status_code == 201, rm.text
        minted = rm.json()
        secret = minted["secret"]
        assert secret.startswith("sk-sentinel-")
        assert "fingerprint" not in rm.text  # never leak the stored fingerprint
        key_id = minted["key"]["key_id"]
        assert "secret" not in minted["key"]  # the metadata object carries no secret

        rl = await client.get(f"/admin/tenants/{tid}/keys", headers=admin_auth_headers)
        assert rl.status_code == 200
        body = rl.text
        assert secret not in body  # the secret is NOT re-readable after creation
        assert "fingerprint" not in body
        assert any(k["key_id"] == key_id for k in rl.json()["keys"])


async def test_revoked_key_rejected(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Vector 7: a revoked key is denied at the gateway lookup immediately."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        rm = await client.post(
            f"/admin/tenants/{tid}/keys", json=_mint_body(team, proj), headers=admin_auth_headers
        )
        secret = rm.json()["secret"]
        key_id = rm.json()["key"]["key_id"]
        rr = await client.post(
            f"/admin/tenants/{tid}/keys/{key_id}/revoke", headers=admin_auth_headers
        )
        assert rr.status_code == 200
        assert rr.json()["is_active"] is False

    # Gateway auth path now rejects the revoked key.
    with pytest.raises(VirtualApiKeyAuthError):
        await VirtualApiKeyRepository(session).lookup_by_plaintext(secret)

    # Admin key events are honestly attributed with the key's REAL team/project.
    rows = (
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
    types = [r.event_type for r in rows]
    assert "admin_key_minted" in types and "admin_key_revoked" in types
    key_events = [r for r in rows if r.event_type in ("admin_key_minted", "admin_key_revoked")]
    for ev in key_events:
        assert ev.agent_id == ADMIN_PRINCIPAL
        assert ev.team_id == team and ev.project_id == proj  # REAL, not WILDCARD


async def test_key_scoped_to_tenant(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Vector 8: a key minted for tenant A is bound to A (cannot become tenant B)."""
    tid_a, team_a, proj_a = await _seed_scope()
    tid_b, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        rm = await client.post(
            f"/admin/tenants/{tid_a}/keys",
            json=_mint_body(team_a, proj_a),
            headers=admin_auth_headers,
        )
        secret = rm.json()["secret"]

    row = await VirtualApiKeyRepository(session).lookup_by_plaintext(secret)
    assert row.tenant_id == tid_a  # resolves ONLY to A
    assert row.tenant_id != tid_b  # never authenticates as another tenant


async def test_rotate_immediate_revoke(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Rotation: old key dies instantly, new key works (immediate-revoke, D4)."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        rm = await client.post(
            f"/admin/tenants/{tid}/keys", json=_mint_body(team, proj), headers=admin_auth_headers
        )
        old_secret = rm.json()["secret"]
        key_id = rm.json()["key"]["key_id"]

        rr = await client.post(
            f"/admin/tenants/{tid}/keys/{key_id}/rotate", headers=admin_auth_headers
        )
        assert rr.status_code == 201
        new_secret = rr.json()["secret"]
        assert new_secret != old_secret

    repo = VirtualApiKeyRepository(session)
    with pytest.raises(VirtualApiKeyAuthError):
        await repo.lookup_by_plaintext(old_secret)  # old dead immediately
    new_row = await repo.lookup_by_plaintext(new_secret)
    assert new_row.is_active and new_row.tenant_id == tid


async def test_mint_rejects_cross_tenant_scope(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Security-audit HIGH: minting for tenant A with tenant B's team/project is rejected."""
    tid_a, _, _ = await _seed_scope()
    _, team_b, proj_b = await _seed_scope()
    async with _client(admin_app) as client:
        r = await client.post(
            f"/admin/tenants/{tid_a}/keys",
            json=_mint_body(team_b, proj_b),  # B's team/project on A's tenant
            headers=admin_auth_headers,
        )
        assert r.status_code == 422


async def test_admin_route_rejects_non_uuid_tenant(admin_app, admin_auth_headers):
    """Security-audit MED-1: a non-UUID {tenant_id} is rejected (422) before any
    session opens or any audit event is appended."""
    async with _client(admin_app) as client:
        r = await client.get("/admin/tenants/not-a-uuid/audit", headers=admin_auth_headers)
        assert r.status_code == 422
        r2 = await client.get("/admin/tenants/not-a-uuid/keys", headers=admin_auth_headers)
        assert r2.status_code == 422


async def test_rotate_revoke_unknown_key_404(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Rotating/revoking a non-existent key for a valid tenant returns 404."""
    tid, _, _ = await _seed_scope()
    fake = str(uuid.uuid4())
    async with _client(admin_app) as client:
        rr = await client.post(
            f"/admin/tenants/{tid}/keys/{fake}/rotate", headers=admin_auth_headers
        )
        assert rr.status_code == 404
        rv = await client.post(
            f"/admin/tenants/{tid}/keys/{fake}/revoke", headers=admin_auth_headers
        )
        assert rv.status_code == 404
