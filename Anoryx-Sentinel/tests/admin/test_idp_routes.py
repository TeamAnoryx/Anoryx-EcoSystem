"""IdP-config admin route tests (F-014 STEP 3, ADR-0017 D3/D6; R6).

DB-backed. Drives the real /admin/tenants/{id}/idp[/groups] routes through the
break-glass require_admin path (the env token from the admin_app fixture).

Asserts (R6 / honest attribution):
  - create config returns METADATA only — the secret is NEVER in the JSON;
  - GET never leaks the secret or ciphertext;
  - the stored client_secret_enc is ciphertext (plaintext absent from the column);
  - idp_config_changed is emitted with agent_id="admin-console", actor_id None;
  - group→role mapping create + list works and also emits idp_config_changed;
  - a missing admin token -> 401 (break-glass auth gate).

The IdP encryption key (SENTINEL_IDP_SECRET_KEY) is assembled at runtime and the
secret_box cache is reset per test — never committed (R6). Skips when no DB.
"""

from __future__ import annotations

import base64
import os
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.sso import secret_box
from persistence.models.events_audit_log import EventsAuditLog
from persistence.models.sso_identity import IdpConfig

pytestmark = pytest.mark.asyncio

_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    """Provide the IdP encryption key the admin_app fixture does not set, and reset cache."""
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, base64.b64encode(os.urandom(32)).decode("ascii"))
    yield
    secret_box.reset_key_cache_for_testing()


async def _seed_tenant() -> str:
    """Commit a tenant row (the target the operator acts on). Returns its id."""
    url = _to_asyncpg(os.environ["DATABASE_URL"])
    engine = create_async_engine(
        url, connect_args={"server_settings": {"app.session_kind": "privileged"}}
    )
    tid = str(uuid.uuid4())
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"idp-{tid[:8]}"},
            )
    finally:
        await engine.dispose()
    return tid


async def _cleanup_tenant(tid: str) -> None:
    url = _to_asyncpg(os.environ["DATABASE_URL"])
    engine = create_async_engine(
        url, connect_args={"server_settings": {"app.session_kind": "privileged"}}
    )
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM idp_group_role_map WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


async def test_create_config_returns_metadata_only(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """POST /idp returns metadata only — the secret is NEVER in the JSON (R6)."""
    tid = await _seed_tenant()
    secret_value = "oidc-secret-" + uuid.uuid4().hex
    try:
        async with _client(admin_app) as client:
            r = await client.post(
                f"/admin/tenants/{tid}/idp",
                json={
                    "protocol": "oidc",
                    "issuer": "https://idp.example.com",
                    "client_id": "client-abc",
                    "client_secret": secret_value,
                    "scopes": "openid profile groups",
                },
                headers=admin_auth_headers,
            )
            assert r.status_code == 201, r.text
            body = r.text
            # The secret and any ciphertext indicator MUST NOT appear in the response.
            assert secret_value not in body
            assert "client_secret_enc" not in body
            assert "client_secret" not in r.json()["config"]
            assert r.json()["config"]["client_secret_set"] is True

            # GET also never leaks the secret.
            rg = await client.get(f"/admin/tenants/{tid}/idp", headers=admin_auth_headers)
            assert rg.status_code == 200
            assert secret_value not in rg.text
            assert rg.json()["count"] == 1
            assert rg.json()["configs"][0]["client_secret_set"] is True

        # The stored column holds ciphertext, not the plaintext (R6).
        row = (
            await session.execute(select(IdpConfig).where(IdpConfig.tenant_id == tid))
        ).scalar_one()
        assert row.client_secret_enc is not None
        assert secret_value.encode("utf-8") not in bytes(row.client_secret_enc)

        # idp_config_changed audit row: admin-console, no operator identity.
        ev = (
            (
                await session.execute(
                    select(EventsAuditLog).where(
                        EventsAuditLog.tenant_id == tid,
                        EventsAuditLog.event_type == "idp_config_changed",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(ev) == 1
        assert ev[0].agent_id == "admin-console"
        assert ev[0].actor_id is None
        assert ev[0].action_taken == "logged"
    finally:
        await _cleanup_tenant(tid)


async def test_group_mapping_create_and_list(
    admin_app, admin_auth_headers, truncate_audit_log_after, session
):
    """POST/GET /idp/groups manages mappings and emits idp_config_changed."""
    tid = await _seed_tenant()
    try:
        async with _client(admin_app) as client:
            r = await client.post(
                f"/admin/tenants/{tid}/idp/groups",
                json={"idp_group": "platform-admins", "role": "tenant_admin"},
                headers=admin_auth_headers,
            )
            assert r.status_code == 201, r.text
            assert r.json()["mapping"]["role"] == "tenant_admin"

            rl = await client.get(f"/admin/tenants/{tid}/idp/groups", headers=admin_auth_headers)
            assert rl.status_code == 200
            assert rl.json()["count"] == 1
            assert rl.json()["mappings"][0]["idp_group"] == "platform-admins"

        ev = (
            (
                await session.execute(
                    select(EventsAuditLog).where(
                        EventsAuditLog.tenant_id == tid,
                        EventsAuditLog.event_type == "idp_config_changed",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(ev) == 1
        assert ev[0].agent_id == "admin-console"
    finally:
        await _cleanup_tenant(tid)


async def test_idp_route_requires_admin_token(admin_app):
    """A missing admin token -> 401 (break-glass auth gate is fail-closed)."""
    tid = str(uuid.uuid4())
    async with _client(admin_app) as client:
        r = await client.get(f"/admin/tenants/{tid}/idp")  # no Authorization header
        assert r.status_code == 401


async def test_invalid_protocol_rejected(admin_app, admin_auth_headers):
    """A non-oidc/saml protocol -> 422 (closed input)."""
    tid = str(uuid.uuid4())
    async with _client(admin_app) as client:
        r = await client.post(
            f"/admin/tenants/{tid}/idp",
            json={"protocol": "ldap", "client_id": "x"},
            headers=admin_auth_headers,
        )
        assert r.status_code == 422


async def test_non_uuid_tenant_rejected(admin_app, admin_auth_headers):
    """A non-UUID {tenant_id} -> 422 before any session/audit (validate_tenant_id_path)."""
    async with _client(admin_app) as client:
        r = await client.get("/admin/tenants/not-a-uuid/idp", headers=admin_auth_headers)
        assert r.status_code == 422
