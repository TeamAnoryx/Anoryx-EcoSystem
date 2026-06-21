"""SSO authz threat-model tests — vectors 14, 15, 16 (F-014 STEP 6, ADR-0017 §7/§8/§10).

These prove the STEP-6 finalization controls:
  14 — unmapped group: a validated identity whose groups map to NO role is DENIED
       (SsoAccessDenied), emits operator_sso_denied exactly once, and provisions NO
       admin_user (the admin_users table has no row for that subject). Fail-closed (R4).
  15 — break-glass: POST /admin/breakglass/login with the valid admin token -> 200 and
       an admin_breakglass_used row (agent_id='admin-console', tenant_id=WILDCARD_UUID,
       action_taken='logged'); no/invalid token -> 401 and NO event. Break-glass works
       with NO IdP configured (R5).
  16 — honest attribution: a successful SSO login emits operator_sso_login with
       actor_id == the provisioned admin_user.id, tenant_id == the operator's REAL
       tenant (never WILDCARD, never nil), agent_id == 'operator-sso'.

Plus a provisioning-idempotency test: two successive logins for the same subject ->
ONE admin_users row, ONE role assignment, last_login updated.

DB-backed (finalize_sso_login + the break-glass route both write the global chain);
skips cleanly with no DB. Audit-committing tests use truncate_audit_log_after. The
verified identity is a tiny offline stand-in carrying the four fields the real
VerifiedOidcIdentity/VerifiedSamlIdentity carry — no live IdP, no assertion crypto.

R6: no idp_subject is logged verbatim; the audit rows carry only the opaque
admin_users.id; no secret material appears anywhere.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.sso.login import ProvisionedPrincipal, SsoAccessDenied, finalize_sso_login
from persistence.models.events_audit_log import EventsAuditLog
from persistence.models.sso_identity import AdminRoleAssignment, AdminUser
from policy.constants import WILDCARD_UUID

pytestmark = pytest.mark.asyncio

_MAPPED_GROUP = "platform-admins"


@dataclass(frozen=True)
class _Identity:
    """Offline stand-in for a fully-validated VerifiedOidcIdentity/VerifiedSamlIdentity.

    Carries exactly the four fields finalize_sso_login reads. tenant_id is the
    idp_config owner (R1); idp_subject is the IdP's stable subject.
    """

    idp_subject: str
    groups: list[str]
    tenant_id: str
    idp_config_id: str


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _seed_tenant(tid: str) -> str:
    """Commit a tenant + one idp_config (the owner the identity binds to). Returns config id."""
    cfg_id = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"authz-{tid[:8]}"},
            )
            await conn.execute(
                text(
                    "INSERT INTO idp_config "
                    "(id, tenant_id, protocol, is_active, issuer, client_id) "
                    "VALUES (:id, :t, 'oidc', true, :iss, :cid)"
                ),
                {"id": cfg_id, "t": tid, "iss": "https://idp.example.com", "cid": "client-x"},
            )
    finally:
        await engine.dispose()
    return cfg_id


async def _map_group(tid: str, group: str, role: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO idp_group_role_map (id, tenant_id, idp_group, role) "
                    "VALUES (:id, :t, :g, :r)"
                ),
                {"id": str(uuid.uuid4()), "t": tid, "g": group, "r": role},
            )
    finally:
        await engine.dispose()


async def _cleanup(tid: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM admin_role_assignments WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(text("DELETE FROM admin_users WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(text("DELETE FROM admin_roles WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(
                text("DELETE FROM idp_group_role_map WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


async def _count_admin_users(session, tid: str, subject: str) -> int:
    rows = (
        (
            await session.execute(
                select(AdminUser).where(
                    AdminUser.tenant_id == tid,
                    AdminUser.idp_subject == subject,
                )
            )
        )
        .scalars()
        .all()
    )
    return len(rows)


# --------------------------------------------------------------------------- #
# Vector 14 — unmapped group -> denied, not provisioned, audited once.
# --------------------------------------------------------------------------- #
async def test_unmapped_group_denied(truncate_audit_log_after, session):
    """A validated identity whose groups map to no role is denied (fail-closed):
    SsoAccessDenied, exactly one operator_sso_denied, and NO admin_user row."""
    tid = str(uuid.uuid4())
    cfg_id = await _seed_tenant(tid)  # NO group mapping
    subject = "op-unmapped-" + uuid.uuid4().hex[:8]
    rid = "req-" + uuid.uuid4().hex[:16]
    identity = _Identity(
        idp_subject=subject, groups=["not-mapped"], tenant_id=tid, idp_config_id=cfg_id
    )
    try:
        with pytest.raises(SsoAccessDenied):
            await finalize_sso_login(identity, request_id=rid)

        # NO admin_user provisioned for the denied subject (fail-closed, R4).
        assert await _count_admin_users(session, tid, subject) == 0

        # operator_sso_denied emitted exactly once, blocked, no operator identity.
        ev = (
            (await session.execute(select(EventsAuditLog).where(EventsAuditLog.request_id == rid)))
            .scalars()
            .all()
        )
        assert len(ev) == 1
        assert ev[0].event_type == "operator_sso_denied"
        assert ev[0].agent_id == "operator-sso"
        assert ev[0].action_taken == "blocked"
        assert ev[0].actor_id is None
        assert ev[0].tenant_id == tid  # the resolved (config-owner) tenant
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 15 — break-glass works with no IdP, and is distinctly audited.
# --------------------------------------------------------------------------- #
async def test_breakglass_token_works_and_audited(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """POST /admin/breakglass/login with the valid admin token -> 200 + one
    admin_breakglass_used row (admin-console, WILDCARD tenant, logged). No IdP
    configured is required (R5)."""
    async with _client(admin_app) as client:
        r = await client.post("/admin/breakglass/login", headers=admin_auth_headers)
        assert r.status_code == 200, r.text
        assert r.json() == {"ok": True}

    ev = (
        (
            await session.execute(
                select(EventsAuditLog).where(EventsAuditLog.event_type == "admin_breakglass_used")
            )
        )
        .scalars()
        .all()
    )
    assert len(ev) == 1
    assert ev[0].agent_id == "admin-console"
    assert ev[0].tenant_id == WILDCARD_UUID  # SYSTEM-scoped auth event
    assert ev[0].action_taken == "logged"
    assert ev[0].actor_id is None


async def test_breakglass_no_token_401_no_event(admin_app, session):
    """No/invalid admin token -> 401 (fail-closed) and NO admin_breakglass_used event."""
    async with _client(admin_app) as client:
        r_missing = await client.post("/admin/breakglass/login")  # no Authorization
        assert r_missing.status_code == 401
        r_bad = await client.post(
            "/admin/breakglass/login", headers={"Authorization": "Bearer wrong-token"}
        )
        assert r_bad.status_code == 401

    ev = (
        (
            await session.execute(
                select(EventsAuditLog).where(EventsAuditLog.event_type == "admin_breakglass_used")
            )
        )
        .scalars()
        .all()
    )
    assert len(ev) == 0


async def test_breakglass_rejects_sso_session(
    admin_app, operator_session_headers, truncate_audit_log_after, session
):
    """MED-1 (audit-integrity; ADR-0017 §8 D7 / vector 15): an SSO operator-session must
    NOT reach the break-glass endpoint — only the env-token break-glass principal may emit
    admin_breakglass_used. SSO session -> 403, and ZERO admin_breakglass_used rows written."""
    headers = operator_session_headers(tenant_id=str(uuid.uuid4()), role="tenant_admin")
    async with _client(admin_app) as client:
        r = await client.post("/admin/breakglass/login", headers=headers)
        assert r.status_code == 403, r.text

    ev = (
        (
            await session.execute(
                select(EventsAuditLog).where(EventsAuditLog.event_type == "admin_breakglass_used")
            )
        )
        .scalars()
        .all()
    )
    assert len(ev) == 0  # no forged system-scoped break-glass row


async def test_whoami_reports_true_principal(
    admin_app, admin_auth_headers, operator_session_headers
):
    """LOW fix: /admin/whoami reports the REAL principal — admin-console for the env-token
    break-glass path, operator-sso for an SSO operator-session (never mislabel a session)."""
    async with _client(admin_app) as client:
        rb = await client.get("/admin/whoami", headers=admin_auth_headers)
        assert rb.status_code == 200
        assert rb.json()["principal"] == "admin-console"

        rs = await client.get(
            "/admin/whoami",
            headers=operator_session_headers(tenant_id=str(uuid.uuid4()), role="tenant_admin"),
        )
        assert rs.status_code == 200
        assert rs.json()["principal"] == "operator-sso"


# --------------------------------------------------------------------------- #
# Vector 16 — honest SSO attribution on a successful login.
# --------------------------------------------------------------------------- #
async def test_sso_login_attribution_honest(truncate_audit_log_after, session):
    """A successful finalize provisions the admin_user and emits operator_sso_login
    with actor_id == the admin_user.id, the REAL tenant (not WILDCARD/nil), and the
    operator-sso slug."""
    tid = str(uuid.uuid4())
    cfg_id = await _seed_tenant(tid)
    await _map_group(tid, _MAPPED_GROUP, "tenant_admin")
    subject = "op-honest-" + uuid.uuid4().hex[:8]
    rid = "req-" + uuid.uuid4().hex[:16]
    identity = _Identity(
        idp_subject=subject, groups=[_MAPPED_GROUP], tenant_id=tid, idp_config_id=cfg_id
    )
    try:
        principal = await finalize_sso_login(identity, request_id=rid)
        assert isinstance(principal, ProvisionedPrincipal)
        assert principal.tenant_id == tid
        assert principal.role == "tenant_admin"
        assert principal.idp_subject == subject
        assert principal.admin_user_id  # a real provisioned id

        row = (
            await session.execute(select(EventsAuditLog).where(EventsAuditLog.request_id == rid))
        ).scalar_one()
        assert row.event_type == "operator_sso_login"
        assert row.agent_id == "operator-sso"
        assert row.action_taken == "logged"
        # Honest attribution: the real operator id, never nil, never the tenant id.
        assert row.actor_id == principal.admin_user_id
        assert row.actor_id != WILDCARD_UUID
        assert row.actor_id != tid
        # The real tenant, never WILDCARD / nil.
        assert row.tenant_id == tid
        assert row.tenant_id != WILDCARD_UUID
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Provisioning idempotency — repeat logins yield one user + one assignment.
# --------------------------------------------------------------------------- #
async def test_provisioning_idempotent(truncate_audit_log_after, session):
    """Two successive logins for the same subject -> ONE admin_users row, ONE role
    assignment (no dupes); last_login is updated."""
    tid = str(uuid.uuid4())
    cfg_id = await _seed_tenant(tid)
    await _map_group(tid, _MAPPED_GROUP, "tenant_admin")
    subject = "op-idem-" + uuid.uuid4().hex[:8]
    identity = _Identity(
        idp_subject=subject, groups=[_MAPPED_GROUP], tenant_id=tid, idp_config_id=cfg_id
    )
    try:
        p1 = await finalize_sso_login(identity, request_id="req-" + uuid.uuid4().hex[:16])
        p2 = await finalize_sso_login(identity, request_id="req-" + uuid.uuid4().hex[:16])

        # Same admin_user across both logins (idempotent upsert).
        assert p1.admin_user_id == p2.admin_user_id

        users = (
            (
                await session.execute(
                    select(AdminUser).where(
                        AdminUser.tenant_id == tid, AdminUser.idp_subject == subject
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(users) == 1
        assert users[0].last_login_at is not None

        assignments = (
            (
                await session.execute(
                    select(AdminRoleAssignment).where(
                        AdminRoleAssignment.tenant_id == tid,
                        AdminRoleAssignment.admin_user_id == p1.admin_user_id,
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(assignments) == 1
        assert assignments[0].role == "tenant_admin"
    finally:
        await _cleanup(tid)
