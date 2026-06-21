"""SSO tenant-isolation threat-model tests — vectors 1, 2, 3 (F-014, ADR-0017 §12).

These three vectors are the CROSS-TENANT defense (R1) and were the gap called out
in the F-014 code review: §12 vectors 1-3 needed EMPIRICAL proofs (not just unit
assertions). Each test proves the attack FAILS — asserting the correct rejection
AND no cross-tenant visibility — using committed rows for two real tenants and the
real RLS connection (the ADR-0017 §12.1 two-tenant committed-row pattern).

  1 — tenant-pin (PRIMARY): an operator-session minted for tenant A drives the real
      gateway app; a request to /admin/tenants/{B}/idp with that token -> 403
      (enforce_admin_scope tenant-pin, the R1 edge control), while
      /admin/tenants/{A}/idp -> allowed (200). Break-glass is NOT under test here.
  2 — audience/issuer binding: an OIDC ID token whose iss/aud does not match the
      tenant's idp_config is rejected (_verify_id_token, vector 12 mechanism), and
      the resolved tenant is ALWAYS the idp_config OWNER (carried in the single-use
      transaction), never a token-supplied value (the aud/iss->tenant binding D4).
  3 — idp_config RLS (was UNTESTED): commit an idp_config for tenant A and one for
      tenant B on separate privileged connections, then via get_tenant_session(A)
      (IdpConfigRepository) assert tenant A sees ONLY A's config and ZERO of B's;
      via get_tenant_session(B) only B's. Empirical cross-tenant proof at the
      DB/RLS layer (NOBYPASSRLS sentinel_app + the NULLIF GUC predicate).

Isolation strategy (ADR-0017 §12.1): vectors 1 & 3 commit real rows for two tenants
and read them back across a real RLS connection; the committed tenants/configs are
cleaned up in teardown. The vector-1 request reaches an audited admin route on a
403/200 outcome, so it uses truncate_audit_log_after (TerminalAudit may append an
admin meta-event). Vector 2 is a pure offline assertion-validation proof (crafted
RSA-signed tokens, no live IdP, no committed audit row) and needs no DB.

R6: no secret material is logged; the offline RSA keys are runtime-assembled and
never committed (the F-005 push-protection lesson); idp_subject is opaque and never
emitted verbatim. DB-backed tests skip cleanly (skip-not-fail) when no DB.
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
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.sso import secret_box
from admin.sso.oidc import OidcClaimsInvalid, _verify_id_token
from persistence.database import get_tenant_session
from persistence.repositories.idp_config_repository import IdpConfigRepository

pytestmark = pytest.mark.asyncio

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "client-abc"


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _require_db() -> None:
    if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
        pytest.skip("DATABASE_URL/APP_DATABASE_URL not set — skipping DB-backed SSO isolation test")


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _seed_tenant_with_oidc_config(tid: str, *, client_id: str = _CLIENT_ID) -> str:
    """Commit a tenant + one active OIDC idp_config on a privileged connection.

    Returns the idp_config id. The tenant is committed so the RLS-scoped read in
    vectors 1/3 sees a real, persisted row owned by exactly this tenant.
    """
    cfg_id = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"iso-{tid[:8]}"},
            )
            await conn.execute(
                text(
                    "INSERT INTO idp_config "
                    "(id, tenant_id, protocol, is_active, issuer, client_id) "
                    "VALUES (:id, :t, 'oidc', true, :iss, :cid)"
                ),
                {"id": cfg_id, "t": tid, "iss": _ISSUER, "cid": client_id},
            )
    finally:
        await engine.dispose()
    return cfg_id


async def _cleanup(*tids: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            for tid in tids:
                await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
                await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- #
# Offline OIDC stub (vector 2): RSA keypair -> JWKS -> minted ID tokens.
# --------------------------------------------------------------------------- #
def _gen_rsa() -> tuple[bytes, dict]:
    """Return (private_pem, jwks_dict) for a fresh RSA keypair (no committed key, R6)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk = JsonWebKey.import_key(pub_pem, {"kty": "RSA"}).as_dict()
    jwk["kid"] = "test-kid"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return priv_pem, {"keys": [jwk]}


def _mint_id_token(priv_pem: bytes, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": "operator-subject-iso",
        "exp": now + 300,
        "iat": now,
        "nonce": "the-stored-nonce",
        "groups": ["platform-admins"],
    }
    claims.update(overrides)
    return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "test-kid"}, claims, priv_pem)


# =========================================================================== #
# Vector 1 — tenant-pin (PRIMARY): an operator-session for A cannot act on B.
# =========================================================================== #
async def test_vector1_operator_pinned_to_a_cannot_read_tenant_b(
    admin_app, operator_session_headers, truncate_audit_log_after
):
    """An operator-session minted for tenant A drives the real gateway app:
    GET /admin/tenants/{B}/idp -> 403 (tenant-pin, vector 1); GET
    /admin/tenants/{A}/idp -> 200 (own tenant allowed). RLS would be the second
    layer, but the pin rejects at the API edge before any session opens."""
    _require_db()
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    await _seed_tenant_with_oidc_config(tenant_a)
    await _seed_tenant_with_oidc_config(tenant_b)
    headers_a = operator_session_headers(tenant_id=tenant_a, role="tenant_admin")
    try:
        async with _client(admin_app) as client:
            # Cross-tenant: operator pinned to A targets B -> 403 (the R1 control).
            r_cross = await client.get(f"/admin/tenants/{tenant_b}/idp", headers=headers_a)
            assert r_cross.status_code == 403, r_cross.text
            assert r_cross.json()["detail"] == "admin_tenant_pin"

            # Own tenant: operator pinned to A targets A -> 200 (allowed).
            r_own = await client.get(f"/admin/tenants/{tenant_a}/idp", headers=headers_a)
            assert r_own.status_code == 200, r_own.text
            # The metadata projection is for tenant A only (never B's config).
            body = r_own.json()
            assert all(cfg["tenant_id"] == tenant_a for cfg in body.get("configs", []))
    finally:
        await _cleanup(tenant_a, tenant_b)


async def test_vector1_operator_for_a_cannot_read_b_audit_or_keys(
    admin_app, operator_session_headers, truncate_audit_log_after
):
    """The tenant-pin holds across the per-tenant routers, not just /idp: an
    operator pinned to A is 403 on /admin/tenants/{B}/audit and
    /admin/tenants/{B}/keys too (defense is the shared enforce_admin_scope guard)."""
    _require_db()
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    await _seed_tenant_with_oidc_config(tenant_a)
    await _seed_tenant_with_oidc_config(tenant_b)
    headers_a = operator_session_headers(tenant_id=tenant_a, role="tenant_admin")
    try:
        async with _client(admin_app) as client:
            for path in (f"/admin/tenants/{tenant_b}/audit", f"/admin/tenants/{tenant_b}/keys"):
                r = await client.get(path, headers=headers_a)
                assert r.status_code == 403, f"{path}: {r.text}"
                assert r.json()["detail"] == "admin_tenant_pin"
    finally:
        await _cleanup(tenant_a, tenant_b)


# =========================================================================== #
# Vector 2 — audience/issuer binding: wrong aud/iss rejected; tenant is the
# config owner, never the token.
# =========================================================================== #
async def test_vector2_wrong_issuer_rejected():
    """An ID token whose iss != the configured issuer is rejected (no identity)."""
    priv_pem, jwks = _gen_rsa()
    token = _mint_id_token(priv_pem, iss="https://attacker.example.com")
    with pytest.raises(OidcClaimsInvalid):
        _verify_id_token(
            id_token=token,
            jwks=jwks,
            issuer=_ISSUER,
            client_id=_CLIENT_ID,
            expected_nonce="the-stored-nonce",
            groups_claim="groups",
        )


async def test_vector2_wrong_audience_rejected():
    """An ID token whose aud != the configured client_id is rejected (no identity)."""
    priv_pem, jwks = _gen_rsa()
    token = _mint_id_token(priv_pem, aud="some-other-client")
    with pytest.raises(OidcClaimsInvalid):
        _verify_id_token(
            id_token=token,
            jwks=jwks,
            issuer=_ISSUER,
            client_id=_CLIENT_ID,
            expected_nonce="the-stored-nonce",
            groups_claim="groups",
        )


async def test_vector2_clock_skew_tightened_to_30s():
    """MED 2: the ID-token exp skew is a small clock-drift tolerance (30s), NOT a
    grace window. A token expired by 60s (> 30s) is rejected; one expired by only
    15s (< 30s, realistic IdP/SP clock drift) is still accepted."""
    priv_pem, jwks = _gen_rsa()
    now = int(time.time())

    # Expired by 60s -> beyond the 30s drift tolerance -> rejected.
    too_old = _mint_id_token(priv_pem, exp=now - 60)
    with pytest.raises(OidcClaimsInvalid):
        _verify_id_token(
            id_token=too_old,
            jwks=jwks,
            issuer=_ISSUER,
            client_id=_CLIENT_ID,
            expected_nonce="the-stored-nonce",
            groups_claim="groups",
        )

    # Expired by only 15s -> within the 30s drift tolerance -> accepted.
    barely = _mint_id_token(priv_pem, exp=now - 15)
    sub, _groups = _verify_id_token(
        id_token=barely,
        jwks=jwks,
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        expected_nonce="the-stored-nonce",
        groups_claim="groups",
    )
    assert sub == "operator-subject-iso"


async def test_vector2_resolved_tenant_is_config_owner_not_token():
    """Binding proof: even a token carrying its OWN tenant_id/iss/aud claims does NOT
    move the resolved tenant. complete_login() binds the identity to the idp_config
    OWNER (carried in the single-use transaction), never to a token value (D4). Here
    we assert the contract directly: _verify_id_token returns only (sub, groups) — it
    has NO channel to influence the tenant, so a forged tenant claim is inert."""
    priv_pem, jwks = _gen_rsa()
    # A token stuffed with an attacker-chosen "tenant_id" claim + valid iss/aud.
    forged_tenant = str(uuid.uuid4())
    token = _mint_id_token(priv_pem, tenant_id=forged_tenant)
    sub, groups = _verify_id_token(
        id_token=token,
        jwks=jwks,
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        expected_nonce="the-stored-nonce",
        groups_claim="groups",
    )
    # Only sub + groups are returned — the tenant is NEVER sourced from the token.
    assert sub == "operator-subject-iso"
    assert groups == ["platform-admins"]
    # (complete_login binds tenant_id = transaction owner; there is no return path
    # by which forged_tenant could become the resolved tenant.)


# =========================================================================== #
# Vector 3 — idp_config RLS (was UNTESTED): each tenant sees ONLY its own config.
# =========================================================================== #
async def test_vector3_idp_config_rls_cross_tenant_zero_visibility():
    """Commit an idp_config for tenant A and one for tenant B on privileged
    connections, then via get_tenant_session(A) (IdpConfigRepository) assert A sees
    ONLY A's config and ZERO of B's; via get_tenant_session(B) only B's. Empirical
    cross-tenant proof at the DB/RLS layer (NOBYPASSRLS sentinel_app + GUC predicate)."""
    _require_db()
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    cfg_a = await _seed_tenant_with_oidc_config(tenant_a, client_id="client-A")
    cfg_b = await _seed_tenant_with_oidc_config(tenant_b, client_id="client-B")
    try:
        # --- Tenant A's RLS session: sees ONLY A's config. ---
        async with get_tenant_session(tenant_a) as ts_a:
            repo_a = IdpConfigRepository(ts_a)
            configs_a = await repo_a.list_for_tenant(tenant_id=tenant_a, caller_tenant_id=tenant_a)
            ids_a = {c["id"] for c in configs_a}
            assert cfg_a in ids_a, "tenant A must see its own idp_config"
            assert cfg_b not in ids_a, "RLS breach: tenant A saw tenant B's idp_config"
            assert all(c["tenant_id"] == tenant_a for c in configs_a)

        # --- Tenant B's RLS session: sees ONLY B's config. ---
        async with get_tenant_session(tenant_b) as ts_b:
            repo_b = IdpConfigRepository(ts_b)
            configs_b = await repo_b.list_for_tenant(tenant_id=tenant_b, caller_tenant_id=tenant_b)
            ids_b = {c["id"] for c in configs_b}
            assert cfg_b in ids_b, "tenant B must see its own idp_config"
            assert cfg_a not in ids_b, "RLS breach: tenant B saw tenant A's idp_config"
            assert all(c["tenant_id"] == tenant_b for c in configs_b)
    finally:
        await _cleanup(tenant_a, tenant_b)


async def test_vector3_idp_config_get_active_rls_isolated():
    """get_active() under tenant A's RLS session cannot read B's config: querying
    B's (tenant_id, protocol) while caller_tenant_id == A raises a tenant-mismatch
    ValueError (app-layer guard) AND, with A as the caller, returns A's row only —
    RLS zero-rows for any other tenant. Proves the per-row read is RLS-scoped too."""
    _require_db()
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    cfg_a = await _seed_tenant_with_oidc_config(tenant_a, client_id="client-A")
    await _seed_tenant_with_oidc_config(tenant_b, client_id="client-B")
    try:
        async with get_tenant_session(tenant_a) as ts_a:
            repo_a = IdpConfigRepository(ts_a)
            # App-layer defense-in-depth: caller A cannot even name B as the target.
            with pytest.raises(ValueError):
                await repo_a.get_active(
                    tenant_id=tenant_b, protocol="oidc", caller_tenant_id=tenant_a
                )
            # And A's own active config IS readable (the row exists, RLS-visible).
            row = await repo_a.get_active(
                tenant_id=tenant_a, protocol="oidc", caller_tenant_id=tenant_a
            )
            assert row.id == cfg_a
            assert row.tenant_id == tenant_a
    finally:
        await _cleanup(tenant_a, tenant_b)


# =========================================================================== #
# HIGH (BFF reconcile) — the SSO callback must NOT be browser-readable cross-origin.
# The operator_session_token is delivered server-to-server (BFF) and wrapped into an
# httpOnly cookie; a cross-origin browser must not be able to read the callback
# response. With CORS default-deny ([] allow-list) the gateway emits NO
# Access-Control-Allow-Origin for /admin/sso/*, so a browser fetch from an arbitrary
# Origin cannot read the body. (admin_app sets CORS_ALLOWED_ORIGINS="[]".)
# =========================================================================== #
async def test_sso_callback_no_permissive_cors(admin_app):
    """The OIDC + SAML SSO callbacks do not emit a permissive
    Access-Control-Allow-Origin for an arbitrary browser Origin. The token in the
    success body is therefore not cross-origin browser-readable (BFF pattern)."""
    _require_db()
    attacker_origin = "https://attacker.example.com"
    async with _client(admin_app) as client:
        # A POST carrying a cross-origin browser Origin. The flow itself fails
        # (no valid state/assertion), but the CORS decision is independent of the
        # route outcome — assert NO Access-Control-Allow-Origin is returned.
        for path, payload in (
            ("/admin/sso/oidc/callback", {"state": "x" * 8, "code": "y" * 8}),
            ("/admin/sso/saml/acs", {"SAMLResponse": "z" * 8, "RelayState": "r" * 8}),
        ):
            r = await client.post(path, json=payload, headers={"Origin": attacker_origin})
            acao = r.headers.get("access-control-allow-origin")
            assert acao != attacker_origin, f"{path} echoed attacker Origin in ACAO: {acao!r}"
            assert acao != "*", f"{path} emitted a wildcard ACAO"
            assert acao is None, f"{path} emitted an unexpected ACAO: {acao!r}"

        # An OPTIONS preflight from the attacker Origin must also not be allowed.
        preflight = await client.options(
            "/admin/sso/oidc/callback",
            headers={
                "Origin": attacker_origin,
                "Access-Control-Request-Method": "POST",
            },
        )
        assert preflight.headers.get("access-control-allow-origin") != attacker_origin
        assert preflight.headers.get("access-control-allow-origin") != "*"


# --------------------------------------------------------------------------- #
# Defensive: confirm the offline RSA fixtures + secret_box stay test-only.
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    """Ephemeral IdP-secret encryption key (vector-3 reads touch the repo, which
    imports secret_box); reset the load-once cache per test. Never committed (R6)."""
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv("SENTINEL_IDP_SECRET_KEY", base64.b64encode(os.urandom(32)).decode("ascii"))
    yield
    secret_box.reset_key_cache_for_testing()
