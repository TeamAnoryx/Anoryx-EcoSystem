"""F-019 operator model-approval endpoints — vectors 1,2,3,4 (ADR-0022 §6).

DB-backed (admin package conftest provisions schema + sentinel_app).

  1  test_data_plane_cannot_approve_model    — a tenant virtual-API-key gets 401 on
                                               the approve route (cannot self-approve).
  2  test_only_operator_can_approve          — break-glass operator approves (200);
                                               an SSO tenant_auditor write is 403.
  3  test_approval_attributed_to_operator    — model_approved (+ model_adopted) are
                                               attributed to the SSO operator + TARGET
                                               tenant (actor_id == operator, agent_id ==
                                               admin-console, never nil-UUID/the tenant).
  4  test_cross_tenant_approval_denied       — an SSO operator pinned to tenant A is
                                               403 on tenant B's approve (no blanket grant).

Skips when no DB is configured.
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

pytestmark = pytest.mark.asyncio

_NIL_UUID = "00000000-0000-0000-0000-000000000000"


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
    """Commit tenant + team + project (team/project needed to mint a virtual key)."""
    engine = _priv_engine()
    tid, team, proj = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"f019-{tid[:8]}"},
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


async def test_data_plane_cannot_approve_model(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Vector 1: a tenant virtual-API-key principal is 401 on the approve route."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        secret = (
            await client.post(
                f"/admin/tenants/{tid}/keys",
                json={"team_id": team, "project_id": proj, "agent_id": "gateway-core"},
                headers=admin_auth_headers,
            )
        ).json()["secret"]

        # The data-plane key cannot reach the operator approve surface — by any
        # header/body/claim. require_admin rejects it before any inventory write.
        r = await client.post(
            f"/admin/tenants/{tid}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert r.status_code == 401, r.text
        # Nothing approved: state never created.
        rl = await client.get(f"/admin/tenants/{tid}/models", headers=admin_auth_headers)
        assert rl.status_code == 200
        assert rl.json()["count"] == 0


async def test_only_operator_can_approve(
    admin_app, admin_auth_headers, operator_session_headers, truncate_audit_log_after
):
    """Vector 2: break-glass operator approves (200); SSO tenant_auditor write is 403."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        # Break-glass operator CAN approve.
        r = await client.post(
            f"/admin/tenants/{tid}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=admin_auth_headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "approved"

        # An SSO tenant_auditor (read-only role) CANNOT write — 403 role gate.
        auditor = operator_session_headers(tenant_id=tid, role="tenant_auditor")
        r2 = await client.post(
            f"/admin/tenants/{tid}/models/deny",
            json={"model_id": "claude-3", "model_type": "base"},
            headers=auditor,
        )
        assert r2.status_code == 403, r2.text


async def test_approval_attributed_to_operator(
    admin_app, operator_session_headers, truncate_audit_log_after, session
):
    """Vector 3: model_approved + model_adopted attributed to the operator + TARGET tenant."""
    tid, _, _ = await _seed_scope()
    operator_uid = str(uuid.uuid4())
    headers = operator_session_headers(
        tenant_id=tid, role="tenant_admin", admin_user_id=operator_uid
    )
    async with _client(admin_app) as client:
        r = await client.post(
            f"/admin/tenants/{tid}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=headers,
        )
        assert r.status_code == 200, r.text

    rows = (
        (await session.execute(select(EventsAuditLog).where(EventsAuditLog.tenant_id == tid)))
        .scalars()
        .all()
    )
    approved = [r for r in rows if r.event_type == "model_approved"]
    adopted = [r for r in rows if r.event_type == "model_adopted"]
    assert approved, "model_approved not emitted"
    assert adopted, "model_adopted not emitted (first registration)"
    for ev in (approved[0], adopted[0]):
        assert ev.actor_id == operator_uid  # the real operator, honest attribution
        assert ev.agent_id == ADMIN_PRINCIPAL  # admin-console subsystem slug
        assert ev.tenant_id == tid  # the TARGET tenant
        assert ev.tenant_id != _NIL_UUID  # never system attribution
        assert ev.model == "gpt-4o"  # model_id rides the existing column


async def test_cross_tenant_approval_denied(
    admin_app, operator_session_headers, truncate_audit_log_after
):
    """Vector 4: an SSO operator pinned to tenant A is 403 on tenant B's approve."""
    tid_a, _, _ = await _seed_scope()
    tid_b, _, _ = await _seed_scope()
    # Operator authenticated for tenant A (token tenant-pinned to A).
    headers_a = operator_session_headers(tenant_id=tid_a, role="tenant_admin")
    async with _client(admin_app) as client:
        r = await client.post(
            f"/admin/tenants/{tid_b}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=headers_a,
        )
        assert r.status_code == 403, r.text  # tenant-pin: no blanket cross-tenant grant
        # Tenant B's inventory stays empty (nothing approved cross-tenant).
        rl = await client.get(
            f"/admin/tenants/{tid_b}/models",
            headers=operator_session_headers(tenant_id=tid_b, role="tenant_admin"),
        )
        assert rl.status_code == 200 and rl.json()["count"] == 0


# ---------------------------------------------------------------------------
# F-021 (ADR-0024): model-retirement operator endpoints. Same router + dependency
# stack as approve/deny, so they inherit the operator-only + tenant-pin guards; these
# vectors prove that holds for the NEW retire / unretire surface specifically.
# ---------------------------------------------------------------------------

_FUTURE = "2099-12-31T23:59:59Z"
_PAST = "2000-01-01T00:00:00Z"


async def test_data_plane_cannot_retire_model(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """F-021 vector 1: a tenant virtual-API-key principal is 401 on the retire route."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        secret = (
            await client.post(
                f"/admin/tenants/{tid}/keys",
                json={"team_id": team, "project_id": proj, "agent_id": "gateway-core"},
                headers=admin_auth_headers,
            )
        ).json()["secret"]

        # The data-plane key cannot reach the operator retire surface.
        r = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _FUTURE},
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert r.status_code == 401, r.text
        # Nor un-retire.
        r2 = await client.post(
            f"/admin/tenants/{tid}/models/unretire",
            json={"model_id": "gpt-4o"},
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert r2.status_code == 401, r2.text


async def test_only_operator_can_retire(
    admin_app, admin_auth_headers, operator_session_headers, truncate_audit_log_after
):
    """F-021 vector 2: break-glass operator retires an approved model (200); an SSO
    tenant_auditor (read-only) retire is 403."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        # Approve first — only an approved model can be retired.
        ap = await client.post(
            f"/admin/tenants/{tid}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=admin_auth_headers,
        )
        assert ap.status_code == 200, ap.text

        # Break-glass operator CAN schedule retirement with a future grace deadline.
        r = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _FUTURE},
            headers=admin_auth_headers,
        )
        assert r.status_code == 200, r.text
        # Honest: state stays approved; retire_at is set (UI derives "retiring").
        assert r.json()["state"] == "approved"
        assert r.json()["retire_at"] is not None

        # An SSO tenant_auditor (read-only role) CANNOT retire — 403 role gate.
        auditor = operator_session_headers(tenant_id=tid, role="tenant_auditor")
        r2 = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _FUTURE},
            headers=auditor,
        )
        assert r2.status_code == 403, r2.text


async def test_cross_tenant_retire_denied(
    admin_app, admin_auth_headers, operator_session_headers, truncate_audit_log_after
):
    """F-021 vector 4: an SSO operator pinned to tenant A is 403 on tenant B's retire."""
    tid_a, _, _ = await _seed_scope()
    tid_b, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        # Approve a model in tenant B via break-glass so the target exists.
        await client.post(
            f"/admin/tenants/{tid_b}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=admin_auth_headers,
        )
        # Operator authenticated for tenant A attempts to retire B's model.
        headers_a = operator_session_headers(tenant_id=tid_a, role="tenant_admin")
        r = await client.post(
            f"/admin/tenants/{tid_b}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _FUTURE},
            headers=headers_a,
        )
        assert r.status_code == 403, r.text  # tenant-pin: no blanket cross-tenant grant


async def test_retire_at_must_be_future(admin_app, admin_auth_headers, truncate_audit_log_after):
    """F-021: a past/now retire_at is rejected 400 (retire is a future grace window;
    immediate blocks use deny)."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        await client.post(
            f"/admin/tenants/{tid}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=admin_auth_headers,
        )
        r = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _PAST},
            headers=admin_auth_headers,
        )
        assert r.status_code == 400, r.text


async def test_retire_requires_approved_model(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """F-021: only an approved model can be retired — absent → 404, non-approved → 409."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        # Absent model (never adopted) → 404.
        r404 = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "never-seen", "retire_at": _FUTURE},
            headers=admin_auth_headers,
        )
        assert r404.status_code == 404, r404.text

        # A denied model is not 'approved' → 409 invalid_model_transition.
        await client.post(
            f"/admin/tenants/{tid}/models/deny",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=admin_auth_headers,
        )
        r409 = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _FUTURE},
            headers=admin_auth_headers,
        )
        assert r409.status_code == 409, r409.text


async def test_retire_unretire_attributed_to_operator(
    admin_app, operator_session_headers, truncate_audit_log_after, session
):
    """F-021: model_retirement_scheduled / _cancelled are attributed to the operator +
    TARGET tenant, and un-retire clears the deadline."""
    tid, _, _ = await _seed_scope()
    operator_uid = str(uuid.uuid4())
    headers = operator_session_headers(
        tenant_id=tid, role="tenant_admin", admin_user_id=operator_uid
    )
    async with _client(admin_app) as client:
        await client.post(
            f"/admin/tenants/{tid}/models/approve",
            json={"model_id": "gpt-4o", "model_type": "base"},
            headers=headers,
        )
        rr = await client.post(
            f"/admin/tenants/{tid}/models/retire",
            json={"model_id": "gpt-4o", "retire_at": _FUTURE},
            headers=headers,
        )
        assert rr.status_code == 200, rr.text
        # Un-retire clears the deadline.
        ru = await client.post(
            f"/admin/tenants/{tid}/models/unretire",
            json={"model_id": "gpt-4o"},
            headers=headers,
        )
        assert ru.status_code == 200, ru.text
        assert ru.json()["retire_at"] is None
        assert ru.json()["state"] == "approved"

    rows = (
        (await session.execute(select(EventsAuditLog).where(EventsAuditLog.tenant_id == tid)))
        .scalars()
        .all()
    )
    scheduled = [r for r in rows if r.event_type == "model_retirement_scheduled"]
    cancelled = [r for r in rows if r.event_type == "model_retirement_cancelled"]
    assert scheduled, "model_retirement_scheduled not emitted"
    assert cancelled, "model_retirement_cancelled not emitted"
    for ev in (scheduled[0], cancelled[0]):
        assert ev.actor_id == operator_uid  # the real operator, honest attribution
        assert ev.agent_id == ADMIN_PRINCIPAL  # admin-console subsystem slug
        assert ev.tenant_id == tid  # the TARGET tenant
        assert ev.tenant_id != _NIL_UUID
        assert ev.model == "gpt-4o"  # model_id rides the existing column
