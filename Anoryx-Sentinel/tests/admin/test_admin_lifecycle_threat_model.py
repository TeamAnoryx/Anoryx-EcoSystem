"""Admin tenant lifecycle — threat model vector 12 + CRUD (ADR-0014 §4/§11).

DB-backed: drives the real /admin/tenants routes through the FastAPI app against
Postgres, then asserts committed state on a privileged session.

Vector 12 (test_no_hard_delete): deactivation is a soft is_active flip — the
tenant row survives, the audit rows for the admin actions survive, and the F-003
hash chain re-validates as intact after the deactivate.

Skips cleanly when DATABASE_URL/APP_DATABASE_URL are absent (pure-unit CI).
The admin_app + admin_auth_headers fixtures live in conftest.py.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from admin.auth import ADMIN_PRINCIPAL
from persistence.models.events_audit_log import EventsAuditLog
from persistence.repositories.audit_log_repository import AuditLogRepository
from policy.constants import WILDCARD_UUID

pytestmark = pytest.mark.asyncio


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_tenant_lifecycle_crud_and_audit(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Create -> get -> list -> happy path + honest admin audit attribution."""
    async with _client(admin_app) as client:
        r = await client.post("/admin/tenants", json={"name": "Acme"}, headers=admin_auth_headers)
        assert r.status_code == 201, r.text
        created = r.json()
        tid = created["tenant_id"]
        uuid.UUID(tid)  # valid UUID shape
        assert created["is_active"] is True
        assert created["name"] == "Acme"

        rg = await client.get(f"/admin/tenants/{tid}", headers=admin_auth_headers)
        assert rg.status_code == 200
        assert rg.json()["tenant_id"] == tid

        rl = await client.get("/admin/tenants?limit=1000", headers=admin_auth_headers)
        assert rl.status_code == 200
        assert tid in {t["tenant_id"] for t in rl.json()["tenants"]}

    rows = (
        (await session.execute(select(EventsAuditLog).where(EventsAuditLog.tenant_id == tid)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    ev = rows[0]
    assert ev.event_type == "admin_tenant_created"
    assert ev.agent_id == ADMIN_PRINCIPAL  # admin-console, not nil-UUID, not the tenant
    assert ev.team_id == WILDCARD_UUID and ev.project_id == WILDCARD_UUID
    assert ev.action_taken == "logged"


async def test_no_hard_delete(admin_app, admin_auth_headers, truncate_audit_log_after, session):
    """Vector 12: deactivate is soft — tenant row + audit rows + chain all survive."""
    async with _client(admin_app) as client:
        tid = (
            await client.post(
                "/admin/tenants", json={"name": "ToDeactivate"}, headers=admin_auth_headers
            )
        ).json()["tenant_id"]

        rd = await client.post(f"/admin/tenants/{tid}/deactivate", headers=admin_auth_headers)
        assert rd.status_code == 200
        assert rd.json()["is_active"] is False

        # The tenant STILL EXISTS (no hard delete) — GET returns it, inactive.
        rg = await client.get(f"/admin/tenants/{tid}", headers=admin_auth_headers)
        assert rg.status_code == 200
        assert rg.json()["is_active"] is False

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
    assert [r.event_type for r in rows] == ["admin_tenant_created", "admin_tenant_deactivated"]
    assert all(r.agent_id == ADMIN_PRINCIPAL for r in rows)

    # The F-003 hash chain re-validates intact after the deactivate (chain survives).
    result = await AuditLogRepository(session).validate_chain()
    assert result.is_valid, result.error_detail


async def test_get_unknown_tenant_404(admin_app, admin_auth_headers):
    """A non-existent tenant id returns 404 (no leak, no 500)."""
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{uuid.uuid4()}", headers=admin_auth_headers)
        assert r.status_code == 404
