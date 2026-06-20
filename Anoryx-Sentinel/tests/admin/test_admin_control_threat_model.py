"""Admin operator control surface — vectors 3, 5, 13, 14 (ADR-0014 §7/§11).

DB-backed.

  3/5  test_config_adjust_audited_and_honest — a config write emits
       admin_config_updated attributed to admin-console + the TARGET tenant
       (not nil-UUID, not the tenant's own identity).
  13   test_deactivated_tenant_keys_rejected — deactivating a tenant cascades to
       its keys; the gateway then denies them.
  14   test_tenant_principal_cannot_list_admin_keys — a tenant Bearer key gets 401
       on the admin key-list route (cannot list another tenant's keys).
  +    test_config_view + test_policies_view — reuse paths return 200.

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
from persistence.repositories.virtual_api_key_repository import (
    VirtualApiKeyAuthError,
    VirtualApiKeyRepository,
)
from policy.constants import WILDCARD_UUID

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


async def _seed_scope(with_routing_policy: bool = False) -> tuple[str, str, str]:
    """Commit tenant + team + project (+ optional routing-policy row). Returns ids."""
    engine = _priv_engine()
    tid, team, proj = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"ct-{tid[:8]}"},
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
            if with_routing_policy:
                await conn.execute(
                    text(
                        "INSERT INTO tenant_routing_policy "
                        "(tenant_id, team_id, project_id, agent_id, allowed_providers, "
                        " fallback_order, audit_mode) "
                        "VALUES (:t, :tm, :p, :a, :ap, :fo, 'full')"
                    ),
                    {
                        "t": tid,
                        "tm": team,
                        "p": proj,
                        "a": "gateway-core",
                        "ap": "openai,anthropic,bedrock",
                        "fo": "openai,anthropic,bedrock",
                    },
                )
    finally:
        await engine.dispose()
    return tid, team, proj


def _mint_body(team: str, proj: str) -> dict:
    return {"team_id": team, "project_id": proj, "agent_id": "gateway-core"}


async def test_config_view(admin_app, admin_auth_headers, truncate_audit_log_after):
    """Config view returns the seeded F-007/F-009 fields (configured=True)."""
    tid, team, proj = await _seed_scope(with_routing_policy=True)
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{tid}/config", headers=admin_auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["configured"] is True
        assert body["audit_mode"] == "full"


async def test_config_adjust_audited_and_honest(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Vectors 3/5: a config write is audited as admin_config_updated, honestly attributed."""
    tid, team, proj = await _seed_scope(with_routing_policy=True)
    async with _client(admin_app) as client:
        rp = await client.patch(
            f"/admin/tenants/{tid}/config",
            json={"team_rpm_limit": 100, "audit_mode": "redacted"},
            headers=admin_auth_headers,
        )
        assert rp.status_code == 200, rp.text
        assert rp.json()["team_rpm_limit"] == 100
        assert rp.json()["audit_mode"] == "redacted"

        rg = await client.get(f"/admin/tenants/{tid}/config", headers=admin_auth_headers)
        assert rg.json()["team_rpm_limit"] == 100  # persisted

    rows = (
        (await session.execute(select(EventsAuditLog).where(EventsAuditLog.tenant_id == tid)))
        .scalars()
        .all()
    )
    cfg = [r for r in rows if r.event_type == "admin_config_updated"]
    assert cfg, "admin_config_updated not emitted"
    ev = cfg[0]
    assert ev.agent_id == ADMIN_PRINCIPAL  # admin-console, not nil-UUID, not the tenant
    assert ev.tenant_id == tid
    assert ev.team_id == WILDCARD_UUID and ev.project_id == WILDCARD_UUID


async def test_config_update_no_row_404(admin_app, admin_auth_headers, truncate_audit_log_after):
    """Adjusting config for a tenant with no routing policy returns 404 (honest scope)."""
    tid, _, _ = await _seed_scope(with_routing_policy=False)
    async with _client(admin_app) as client:
        r = await client.patch(
            f"/admin/tenants/{tid}/config",
            json={"team_rpm_limit": 50},
            headers=admin_auth_headers,
        )
        assert r.status_code == 404


async def test_policies_view(admin_app, admin_auth_headers, truncate_audit_log_after):
    """Policy intake status view returns 200 (empty for a fresh tenant)."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{tid}/policies", headers=admin_auth_headers)
        assert r.status_code == 200, r.text
        assert r.json()["count"] == 0


async def test_deactivated_tenant_keys_rejected(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """Vector 13: deactivating a tenant cascades to its keys; the gateway denies them."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        secret = (
            await client.post(
                f"/admin/tenants/{tid}/keys",
                json=_mint_body(team, proj),
                headers=admin_auth_headers,
            )
        ).json()["secret"]

        # Sanity: the key authenticates before deactivation.
        assert (await VirtualApiKeyRepository(session).lookup_by_plaintext(secret)).tenant_id == tid

        rd = await client.post(f"/admin/tenants/{tid}/deactivate", headers=admin_auth_headers)
        assert rd.status_code == 200

    # The tenant's key is now denied at the gateway lookup.
    with pytest.raises(VirtualApiKeyAuthError):
        await VirtualApiKeyRepository(session).lookup_by_plaintext(secret)


async def test_tenant_principal_cannot_list_admin_keys(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Vector 14: a tenant Bearer key gets 401 on the admin key-list route."""
    tid, team, proj = await _seed_scope()
    async with _client(admin_app) as client:
        secret = (
            await client.post(
                f"/admin/tenants/{tid}/keys",
                json=_mint_body(team, proj),
                headers=admin_auth_headers,
            )
        ).json()["secret"]

        # A tenant principal (its own minted key) cannot reach the admin surface.
        r = await client.get(
            f"/admin/tenants/{tid}/keys", headers={"Authorization": f"Bearer {secret}"}
        )
        assert r.status_code == 401
        assert "key_id" not in r.text


async def test_config_view_unconfigured(admin_app, admin_auth_headers, truncate_audit_log_after):
    """Config view for a tenant with no routing policy reports configured=False."""
    tid, _, _ = await _seed_scope(with_routing_policy=False)
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{tid}/config", headers=admin_auth_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["configured"] is False
        assert body["audit_mode"] is None
        assert body["team_rpm_limit"] is None


async def test_operator_compliance_evidence(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """Operator compliance-evidence path (F-011 reuse) returns an audit-ready summary."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        r = await client.post(
            f"/admin/tenants/{tid}/compliance/evidence",
            json={"framework": "SOC2", "t0": "2025-01-01T00:00:00Z", "t1": "2027-01-01T00:00:00Z"},
            headers=admin_auth_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["tenant_id"] == tid
        assert body["framework"] == "SOC2"
        assert "readiness_score" in body
        assert "disclaimer" in body
        # Honest language: the disclaimer points to an accredited auditor.
        assert "auditor" in body["disclaimer"].lower()


async def test_operator_evidence_bad_window(
    admin_app, admin_auth_headers, truncate_audit_log_after
):
    """A reversed/invalid evidence window returns 400."""
    tid, _, _ = await _seed_scope()
    async with _client(admin_app) as client:
        r = await client.post(
            f"/admin/tenants/{tid}/compliance/evidence",
            json={"framework": "SOC2", "t0": "2027-01-01T00:00:00Z", "t1": "2025-01-01T00:00:00Z"},
            headers=admin_auth_headers,
        )
        assert r.status_code == 400
