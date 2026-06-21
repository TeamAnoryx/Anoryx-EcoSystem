"""Auth-boundary authz tests (F-014 STEP 7, ADR-0017 §3 D2 / §12 vectors 1-2).

These drive the REAL gateway app and prove the require_admin SSO branch +
enforce_admin_scope controls — the R1 cross-tenant defense at the API edge:

  test_operator_session_tenant_pin (vector 1, PRIMARY): an operator-session pinned
    to tenant A is FORBIDDEN (403) on tenant B's per-tenant routes and ALLOWED on
    tenant A's — an operator NEVER acts cross-tenant.
  test_sso_global_op_forbidden: an operator-session on the GLOBAL tenants_router
    (create / deactivate) -> 403 (global = break-glass only, ADR-0017 §3 D2.5).
  test_role_enforcement: a tenant_auditor operator-session -> GET allowed, write
    (mint key) -> 403; a tenant_admin -> write allowed.
  test_breakglass_still_cross_tenant (R5): the env token acts on ANY tenant's
    per-tenant routes AND the global routes (unchanged); attribution stays
    admin-console with actor_id NULL.
  test_breakglass_token_not_a_session / test_session_not_breakglass: mutual
    exclusivity — a session is rejected where only break-glass is allowed (global),
    and the env token is never parsed as a session.
  test_operator_action_attribution: an SSO operator minting a key on its OWN tenant
    -> the admin_key_minted audit row carries actor_id == the operator's
    admin_user_id (honest attribution, vector 16).

DB-backed; skips cleanly with no DB. Audit-committing tests use
truncate_audit_log_after. The operator-session is minted by the conftest
operator_session_headers factory under the same secret admin_app provisions.

R6: no secret material is logged; the actor_id carried is the opaque admin_user_id.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

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


async def _seed_scope() -> tuple[str, str, str]:
    """Commit a tenant + team + project (FK prerequisites for key mint). Returns ids."""
    engine = _priv_engine()
    tid, team, proj = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"op-{tid[:8]}"},
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


async def _cleanup(*tenant_ids: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            for tid in tenant_ids:
                await conn.execute(
                    text("DELETE FROM virtual_api_keys WHERE tenant_id = :t"), {"t": tid}
                )
                await conn.execute(text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


def _mint_body(team: str, proj: str) -> dict:
    return {"team_id": team, "project_id": proj, "agent_id": "gateway-core"}


# --------------------------------------------------------------------------- #
# Vector 1 (PRIMARY) — operator-session is strictly tenant-pinned.
# --------------------------------------------------------------------------- #
async def test_operator_session_tenant_pin(
    admin_app, operator_session_headers, truncate_audit_log_after
):
    """An operator pinned to tenant A: 403 on tenant B, allowed on tenant A.

    The R1 control proven adversarially — an operator-session NEVER acts on a
    tenant other than the one its token is pinned to.
    """
    tid_a, team_a, proj_a = await _seed_scope()
    tid_b, _team_b, _proj_b = await _seed_scope()
    headers = operator_session_headers(tenant_id=tid_a, role="tenant_admin")
    try:
        async with _client(admin_app) as client:
            # Cross-tenant: operator for A attempts B's per-tenant routes -> 403.
            r_b_keys = await client.get(f"/admin/tenants/{tid_b}/keys", headers=headers)
            assert r_b_keys.status_code == 403, r_b_keys.text
            r_b_audit = await client.get(f"/admin/tenants/{tid_b}/audit", headers=headers)
            assert r_b_audit.status_code == 403, r_b_audit.text

            # Own tenant: allowed (read) and (write — tenant_admin).
            r_a_keys = await client.get(f"/admin/tenants/{tid_a}/keys", headers=headers)
            assert r_a_keys.status_code == 200, r_a_keys.text
            r_a_mint = await client.post(
                f"/admin/tenants/{tid_a}/keys", json=_mint_body(team_a, proj_a), headers=headers
            )
            assert r_a_mint.status_code == 201, r_a_mint.text
    finally:
        await _cleanup(tid_a, tid_b)


# --------------------------------------------------------------------------- #
# Vector 2 / D2.5 — global tenant-registry is break-glass only.
# --------------------------------------------------------------------------- #
async def test_sso_global_op_forbidden(admin_app, operator_session_headers):
    """An operator-session on the GLOBAL tenants_router -> 403 (break-glass only)."""
    tid = str(uuid.uuid4())
    headers = operator_session_headers(tenant_id=tid, role="tenant_admin")
    async with _client(admin_app) as client:
        r_create = await client.post(
            "/admin/tenants", json={"name": "x", "display_name": "X"}, headers=headers
        )
        assert r_create.status_code == 403, r_create.text
        r_list = await client.get("/admin/tenants", headers=headers)
        assert r_list.status_code == 403, r_list.text
        r_deact = await client.post(f"/admin/tenants/{tid}/deactivate", headers=headers)
        assert r_deact.status_code == 403, r_deact.text


# --------------------------------------------------------------------------- #
# Role enforcement — tenant_auditor is read-only; tenant_admin may write.
# --------------------------------------------------------------------------- #
async def test_role_enforcement(admin_app, operator_session_headers, truncate_audit_log_after):
    """tenant_auditor: GET allowed, write (mint) -> 403. tenant_admin: write allowed."""
    tid, team, proj = await _seed_scope()
    auditor = operator_session_headers(tenant_id=tid, role="tenant_auditor")
    admin = operator_session_headers(tenant_id=tid, role="tenant_admin")
    try:
        async with _client(admin_app) as client:
            # Auditor: read OK.
            r_get = await client.get(f"/admin/tenants/{tid}/keys", headers=auditor)
            assert r_get.status_code == 200, r_get.text
            # Auditor: write FORBIDDEN (role gate).
            r_mint = await client.post(
                f"/admin/tenants/{tid}/keys", json=_mint_body(team, proj), headers=auditor
            )
            assert r_mint.status_code == 403, r_mint.text
            # Admin: write ALLOWED.
            r_admin_mint = await client.post(
                f"/admin/tenants/{tid}/keys", json=_mint_body(team, proj), headers=admin
            )
            assert r_admin_mint.status_code == 201, r_admin_mint.text
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# R5 — break-glass is unchanged: cross-tenant on per-tenant AND global routes.
# --------------------------------------------------------------------------- #
async def test_breakglass_still_cross_tenant(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """The env token acts on ANY tenant's per-tenant routes AND global routes,
    with attribution staying admin-console (actor_id NULL) — unchanged (R5/R8)."""
    tid_a, team_a, proj_a = await _seed_scope()
    tid_b, team_b, proj_b = await _seed_scope()
    created_tid = None
    try:
        async with _client(admin_app) as client:
            # Per-tenant: break-glass mints on BOTH tenants (cross-tenant).
            r_a = await client.post(
                f"/admin/tenants/{tid_a}/keys",
                json=_mint_body(team_a, proj_a),
                headers=admin_auth_headers,
            )
            assert r_a.status_code == 201, r_a.text
            r_b = await client.post(
                f"/admin/tenants/{tid_b}/keys",
                json=_mint_body(team_b, proj_b),
                headers=admin_auth_headers,
            )
            assert r_b.status_code == 201, r_b.text
            # Global: break-glass creates a tenant (allowed).
            r_create = await client.post(
                "/admin/tenants",
                json={"name": f"bg-{uuid.uuid4().hex[:8]}"},
                headers=admin_auth_headers,
            )
            assert r_create.status_code == 201, r_create.text
            created_tid = r_create.json()["tenant_id"]

        # Attribution unchanged: admin_key_minted rows carry NO actor_id (break-glass).
        rows = (
            (
                await session.execute(
                    select(EventsAuditLog).where(
                        EventsAuditLog.event_type == "admin_key_minted",
                        EventsAuditLog.tenant_id.in_([tid_a, tid_b]),
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        for row in rows:
            assert row.agent_id == "admin-console"
            assert row.actor_id is None  # break-glass: no per-operator identity
    finally:
        ids = [tid_a, tid_b] + ([created_tid] if created_tid else [])
        await _cleanup(*ids)


# --------------------------------------------------------------------------- #
# Mutual exclusivity — no fall-through between the two credentials.
# --------------------------------------------------------------------------- #
async def test_breakglass_token_not_a_session(admin_app, admin_auth_headers):
    """The env break-glass token is NOT parsed as an operator-session: it is the
    ONLY credential the global routes accept (it must not be rejected there)."""
    async with _client(admin_app) as client:
        # Global route: the env token authorizes (it is not treated as a session).
        r = await client.get("/admin/tenants", headers=admin_auth_headers)
        assert r.status_code == 200, r.text


async def test_session_not_breakglass(admin_app, operator_session_headers):
    """An operator-session is NOT accepted where only break-glass is allowed
    (global routes) — it never falls through to the break-glass branch."""
    headers = operator_session_headers(tenant_id=str(uuid.uuid4()), role="tenant_admin")
    async with _client(admin_app) as client:
        # whoami is reachable (require_admin authenticates the session) — proving
        # the session IS a valid admin credential (not rejected as unknown) ...
        r_who = await client.get("/admin/whoami", headers=headers)
        assert r_who.status_code == 200, r_who.text
        # ... but the global registry rejects the session (break-glass only): the
        # session never falls through to the break-glass branch.
        r_global = await client.get("/admin/tenants", headers=headers)
        assert r_global.status_code == 403, r_global.text


async def test_neither_credential_fails_closed(admin_app):
    """Neither the env token nor a valid session -> 401 (fail-closed, R4)."""
    async with _client(admin_app) as client:
        r_none = await client.get("/admin/whoami")
        assert r_none.status_code == 401
        r_bad = await client.get(
            "/admin/whoami", headers={"Authorization": "Bearer not-a-token-nor-a-session"}
        )
        assert r_bad.status_code == 401


# --------------------------------------------------------------------------- #
# Vector 16 — honest attribution on an existing admin action by an SSO operator.
# --------------------------------------------------------------------------- #
async def test_operator_action_attribution(
    admin_app, operator_session_headers, truncate_audit_log_after, session
):
    """An SSO operator minting a key on its OWN tenant -> the admin_key_minted row
    carries actor_id == the operator's admin_user_id (honest attribution)."""
    tid, team, proj = await _seed_scope()
    operator_id = str(uuid.uuid4())
    headers = operator_session_headers(
        tenant_id=tid, role="tenant_admin", admin_user_id=operator_id
    )
    try:
        async with _client(admin_app) as client:
            r = await client.post(
                f"/admin/tenants/{tid}/keys", json=_mint_body(team, proj), headers=headers
            )
            assert r.status_code == 201, r.text

        row = (
            await session.execute(
                select(EventsAuditLog).where(
                    EventsAuditLog.event_type == "admin_key_minted",
                    EventsAuditLog.tenant_id == tid,
                )
            )
        ).scalar_one()
        assert row.agent_id == "admin-console"  # slug stays; actor_id names operator
        assert row.actor_id == operator_id  # honest per-operator attribution
        assert row.actor_id != tid  # never the tenant's own id
    finally:
        await _cleanup(tid)
