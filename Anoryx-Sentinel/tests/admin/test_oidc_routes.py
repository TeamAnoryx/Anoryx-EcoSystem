"""OIDC SSO login route tests (F-014 STEP 4, ADR-0017 §3/§5).

Drives the UNAUTHENTICATED sso_login_router through the real gateway app:
  - the routes are reachable WITHOUT an admin token (the /admin/sso prefix is
    exempt from AuthMiddleware/TenantContextMiddleware; require_admin is NOT on
    this router);
  - a tenant with no OIDC config returns a uniform 404 sso_unavailable
    (anti-enumeration);
  - a full begin->callback with a mapped group returns the verified identity +
    role and NO operator session cookie (STEP-4 scope: no session minted yet);
  - an unmapped group -> 403 + operator_sso_denied (fail-closed, vector 14), no
    session;
  - an invalid assertion (forged state) -> generic 401, no session.

DB-backed; skips cleanly with no DB. The IdP network calls are monkeypatched
offline. Audit-committing tests use truncate_audit_log_after.
"""

from __future__ import annotations

import base64
import os
import re
import time
import uuid

import pytest
from authlib.jose import JsonWebKey, JsonWebToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.sso import oidc, oidc_routes, secret_box
from persistence.models.events_audit_log import EventsAuditLog

pytestmark = pytest.mark.asyncio

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "client-abc"
_REDIRECT_URI = "https://sp.example.com/admin/sso/oidc/callback"
_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _gen_rsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = JsonWebKey.import_key(pub, {"kty": "RSA"}).as_dict()
    jwk["kid"] = "test-kid"
    return priv, {"keys": [jwk]}


def _mint(priv, **over):
    now = int(time.time())
    claims = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": "op-1",
        "exp": now + 300,
        "iat": now,
        "nonce": "X",
        "groups": ["platform-admins"],
    }
    claims.update(over)
    return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "test-kid"}, claims, priv)


async def _seed(tid: str, *, with_config: bool = True) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"oidc-{tid[:8]}"},
            )
            if with_config:
                await conn.execute(
                    text(
                        "INSERT INTO idp_config "
                        "(id, tenant_id, protocol, is_active, issuer, client_id, "
                        " client_secret_enc, scopes, sp_acs_url) "
                        "VALUES (:id, :t, 'oidc', true, :iss, :cid, :sec, :sc, :acs)"
                    ),
                    {
                        "id": str(uuid.uuid4()),
                        "t": tid,
                        "iss": _ISSUER,
                        "cid": _CLIENT_ID,
                        "sec": secret_box.encrypt("secret-" + uuid.uuid4().hex),
                        "sc": "openid groups",
                        "acs": _REDIRECT_URI,
                    },
                )
    finally:
        await engine.dispose()


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


async def _nonce(state: str) -> str:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            row = (
                await conn.execute(
                    text("SELECT nonce FROM oidc_login_transaction WHERE state = :s"), {"s": state}
                )
            ).first()
            return row[0]
    finally:
        await engine.dispose()


async def _cleanup(tid: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM oidc_login_transaction WHERE tenant_id = :t"), {"t": tid}
            )
            # STEP-6 JIT provisioning rows (FK order: assignments -> users -> roles).
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


@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, base64.b64encode(os.urandom(32)).decode("ascii"))
    oidc_routes.reset_rate_limit_for_testing()
    yield
    secret_box.reset_key_cache_for_testing()
    oidc_routes.reset_rate_limit_for_testing()


@pytest.fixture()
def offline_idp(monkeypatch):
    priv, jwks = _gen_rsa()
    box = {"token": None}
    monkeypatch.setattr(
        oidc,
        "discover_oidc",
        lambda issuer: {
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
        },
    )
    monkeypatch.setattr(oidc, "fetch_jwks", lambda _uri: jwks)
    monkeypatch.setattr(
        oidc,
        "exchange_code",
        lambda **kw: {"id_token": box["token"]},
    )

    class _I:
        priv_key = priv

        @staticmethod
        def set(tok):
            box["token"] = tok

    return _I()


def _extract_state(auth_url: str) -> str:
    m = re.search(r"[?&]state=([^&]+)", auth_url)
    assert m, auth_url
    return m.group(1)


# --------------------------------------------------------------------------- #
# Reachability without admin auth + anti-enumeration
# --------------------------------------------------------------------------- #
async def test_login_route_unauthenticated_and_reachable(admin_app, offline_idp):
    """/admin/sso/oidc/login works with NO Authorization header (router is not
    behind require_admin; /admin/sso is auth/tenant-context exempt)."""
    tid = str(uuid.uuid4())
    await _seed(tid)
    try:
        async with _client(admin_app) as client:
            r = await client.post("/admin/sso/oidc/login", json={"tenant_id": tid})
            assert r.status_code == 200, r.text
            assert r.json()["authorization_url"].startswith(f"{_ISSUER}/authorize")
    finally:
        await _cleanup(tid)


async def test_login_no_config_uniform_404(admin_app):
    """A tenant with no OIDC config -> uniform 404 sso_unavailable (anti-enumeration)."""
    tid = str(uuid.uuid4())
    await _seed(tid, with_config=False)
    try:
        async with _client(admin_app) as client:
            r = await client.post("/admin/sso/oidc/login", json={"tenant_id": tid})
            assert r.status_code == 404
            assert r.json()["detail"] == "sso_unavailable"
    finally:
        await _cleanup(tid)


async def test_login_non_uuid_tenant_uniform_404(admin_app):
    """A non-UUID tenant_id -> the SAME uniform 404 (no enumeration signal)."""
    async with _client(admin_app) as client:
        r = await client.post("/admin/sso/oidc/login", json={"tenant_id": "not-a-uuid"})
        assert r.status_code == 404
        assert r.json()["detail"] == "sso_unavailable"


# --------------------------------------------------------------------------- #
# Full happy callback (no operator session minted in STEP 4)
# --------------------------------------------------------------------------- #
async def test_callback_success_returns_operator_session(
    admin_app, offline_idp, truncate_audit_log_after, session
):
    """STEP-7: a mapped group -> provisioned principal + operator_sso_login row +
    a minted, tenant-pinned operator-session token returned to the caller (PART B
    stores it in the cookie spine). idp_subject is NOT returned (no PII, R6)."""
    from admin.sso.session import verify as verify_op

    tid = str(uuid.uuid4())
    await _seed(tid)
    await _map_group(tid, "platform-admins", "tenant_admin")
    try:
        async with _client(admin_app) as client:
            rl = await client.post("/admin/sso/oidc/login", json={"tenant_id": tid})
            state = _extract_state(rl.json()["authorization_url"])
            offline_idp.set(_mint(offline_idp.priv_key, nonce=await _nonce(state)))

            rc = await client.post("/admin/sso/oidc/callback", json={"state": state, "code": "abc"})
            assert rc.status_code == 200, rc.text
            body = rc.json()
            assert body["tenant_id"] == tid
            assert body["role"] == "tenant_admin"
            assert body["token_type"] == "Bearer"  # noqa: S105 — response field, not a secret
            assert body["expires_in"] > 0
            token = body["operator_session_token"]
            assert token
            # No PII to the browser (R6): idp_subject / admin_user_id are NOT echoed.
            assert "idp_subject" not in body
            # The minted session verifies and is tenant-pinned to the real tenant.
            claims = verify_op(token)
            assert claims.tenant_id == tid
            assert claims.role == "tenant_admin"
            assert claims.auth_method == "sso"

        # operator_sso_login row: actor_id == the session's admin_user_id (vector 16).
        ev = (
            (
                await session.execute(
                    select(EventsAuditLog).where(
                        EventsAuditLog.tenant_id == tid,
                        EventsAuditLog.event_type == "operator_sso_login",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(ev) == 1
        assert ev[0].agent_id == "operator-sso"
        assert ev[0].action_taken == "logged"
        assert ev[0].actor_id == claims.admin_user_id
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 14 — unmapped group -> 403 + operator_sso_denied, no session
# --------------------------------------------------------------------------- #
async def test_callback_unmapped_group_denied(
    admin_app, offline_idp, truncate_audit_log_after, session
):
    tid = str(uuid.uuid4())
    await _seed(tid)  # NO group mapping seeded
    try:
        async with _client(admin_app) as client:
            rl = await client.post("/admin/sso/oidc/login", json={"tenant_id": tid})
            state = _extract_state(rl.json()["authorization_url"])
            offline_idp.set(
                _mint(offline_idp.priv_key, nonce=await _nonce(state), groups=["unmapped"])
            )
            rc = await client.post("/admin/sso/oidc/callback", json={"state": state, "code": "abc"})
            assert rc.status_code == 403
            assert "set-cookie" not in {k.lower() for k in rc.headers}

        ev = (
            (
                await session.execute(
                    select(EventsAuditLog).where(
                        EventsAuditLog.tenant_id == tid,
                        EventsAuditLog.event_type == "operator_sso_denied",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(ev) == 1
        assert ev[0].agent_id == "operator-sso"
        assert ev[0].action_taken == "blocked"
        assert ev[0].actor_id is None
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Forged state -> generic 401, no session
# --------------------------------------------------------------------------- #
async def test_callback_forged_state_generic_401(admin_app, offline_idp):
    tid = str(uuid.uuid4())
    await _seed(tid)
    try:
        offline_idp.set(_mint(offline_idp.priv_key))
        async with _client(admin_app) as client:
            rc = await client.post(
                "/admin/sso/oidc/callback",
                json={"state": "never-issued-state", "code": "abc"},
            )
            assert rc.status_code == 401
            assert rc.json()["detail"] == "sso_authentication_failed"
            assert "set-cookie" not in {k.lower() for k in rc.headers}
    finally:
        await _cleanup(tid)
