"""OIDC default network-hook + edge-branch coverage (F-014 STEP 4, additive).

Companion to test_oidc_threat_model.py. That suite injects stubs in place of the
three outbound calls (discover_oidc / fetch_jwks / exchange_code) so the network
is never touched — which leaves the DEFAULT httpx bodies of those hooks, plus a
handful of pure error/edge branches, uncovered. This file closes that gap WITHOUT
a live IdP:

  * the default discover_oidc / fetch_jwks / exchange_code bodies run against a
    MOCKED httpx (pytest-httpx) — a fake .well-known/openid-configuration, JWKS,
    and token endpoint — including their fail-closed error paths;
  * the pure helpers _normalize_scope and _verify_id_token are exercised directly
    for their remaining branches (scope injection, iat-in-future, missing sub,
    scalar/None groups coercion);
  * the begin_login / complete_login config-edge branches (no active config,
    incomplete config, discovery missing endpoints, config-disappeared-mid-flow)
    are exercised against a real DB seed and the offline stubs.

No live IdP, no committed secret/key (R6). The pure-helper + httpx-mock tests have
NO DB dependency; the begin/complete edge tests are DB-backed and skip when no DB.
"""

from __future__ import annotations

import base64
import os
import re
import time
import uuid

import httpx
import pytest
from authlib.jose import JsonWebKey, JsonWebToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.sso import oidc, secret_box
from admin.sso.oidc import (
    OidcClaimsInvalid,
    OidcConfigUnavailable,
    OidcPkceInvalid,
    OidcSignatureInvalid,
    _normalize_scope,
    _verify_id_token,
    begin_login,
    complete_login,
    discover_oidc,
    exchange_code,
    fetch_jwks,
)

pytestmark = pytest.mark.asyncio

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "client-abc"
_REDIRECT_URI = "https://sp.example.com/admin/sso/oidc/callback"
_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


# --------------------------------------------------------------------------- #
# Offline keypair -> JWKS -> minted token (mirrors test_oidc_threat_model).
# --------------------------------------------------------------------------- #
def _gen_rsa() -> tuple[bytes, dict]:
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


def _mint(priv_pem: bytes, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": "operator-subject-1",
        "exp": now + 300,
        "iat": now,
        "nonce": "n0",
        "groups": ["platform-admins"],
    }
    claims.update(overrides)
    return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "test-kid"}, claims, priv_pem)


@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    """Ephemeral IdP-secret key; reset the load-once cache per test."""
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, base64.b64encode(os.urandom(32)).decode("ascii"))
    yield
    secret_box.reset_key_cache_for_testing()


# --------------------------------------------------------------------------- #
# Default network hooks against MOCKED httpx (pytest-httpx). These exercise the
# real discover_oidc / fetch_jwks / exchange_code bodies (lines 166-227).
# --------------------------------------------------------------------------- #
def test_discover_oidc_default_body_success(httpx_mock):
    """The default discover_oidc body GETs .well-known/openid-configuration."""
    doc = {
        "authorization_endpoint": f"{_ISSUER}/authorize",
        "token_endpoint": f"{_ISSUER}/token",
        "jwks_uri": f"{_ISSUER}/jwks",
    }
    httpx_mock.add_response(url=_ISSUER + "/.well-known/openid-configuration", json=doc)
    # Trailing slash is stripped before the discovery path is appended.
    assert discover_oidc(_ISSUER + "/") == doc


def test_discover_oidc_failclosed_on_http_error(httpx_mock):
    """A non-2xx discovery response fails closed as OidcConfigUnavailable."""
    httpx_mock.add_response(url=_ISSUER + "/.well-known/openid-configuration", status_code=500)
    with pytest.raises(OidcConfigUnavailable):
        discover_oidc(_ISSUER)


def test_fetch_jwks_default_body_success(httpx_mock):
    """The default fetch_jwks body GETs the JWKS document."""
    _priv, jwks = _gen_rsa()
    httpx_mock.add_response(url=_ISSUER + "/jwks", json=jwks)
    assert fetch_jwks(_ISSUER + "/jwks") == jwks


def test_fetch_jwks_failclosed_on_network_error(httpx_mock):
    """A network failure fetching the JWKS fails closed as OidcSignatureInvalid."""
    httpx_mock.add_exception(httpx.ConnectError("boom"), url=_ISSUER + "/jwks")
    with pytest.raises(OidcSignatureInvalid):
        fetch_jwks(_ISSUER + "/jwks")


def test_exchange_code_default_body_sends_verifier_and_returns(httpx_mock):
    """The default exchange_code body POSTs the form (incl. the PKCE verifier) and
    returns the token response; the verifier + secret are sent in the body."""
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(200, json={"id_token": "tok", "token_type": "Bearer"})

    httpx_mock.add_callback(_capture, url=_ISSUER + "/token")
    out = exchange_code(
        token_endpoint=_ISSUER + "/token",
        code="auth-code",
        redirect_uri=_REDIRECT_URI,
        client_id=_CLIENT_ID,
        client_secret="sek",
        code_verifier="verifier-xyz",
    )
    assert out["id_token"] == "tok"  # noqa: S105 — test-only dummy token value
    assert "code_verifier=verifier-xyz" in captured["body"]
    assert "client_secret=sek" in captured["body"]  # secret sent (branch with secret)


def test_exchange_code_no_secret_omits_secret(httpx_mock):
    """With client_secret=None the form omits client_secret (the None branch)."""
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(200, json={"id_token": "tok"})

    httpx_mock.add_callback(_capture, url=_ISSUER + "/token")
    out = exchange_code(
        token_endpoint=_ISSUER + "/token",
        code="c",
        redirect_uri=_REDIRECT_URI,
        client_id=_CLIENT_ID,
        client_secret=None,
        code_verifier="v",
    )
    assert out["id_token"] == "tok"  # noqa: S105 — test-only dummy token value
    assert "client_secret=" not in captured["body"]


def test_exchange_code_failclosed_on_http_error(httpx_mock):
    """A token-endpoint HTTP error fails closed as OidcPkceInvalid."""
    httpx_mock.add_response(url=_ISSUER + "/token", status_code=400)
    with pytest.raises(OidcPkceInvalid):
        exchange_code(
            token_endpoint=_ISSUER + "/token",
            code="c",
            redirect_uri=_REDIRECT_URI,
            client_id=_CLIENT_ID,
            client_secret=None,
            code_verifier="v",
        )


def test_exchange_code_missing_id_token_rejected(httpx_mock):
    """A 200 token response with no id_token is rejected (OidcClaimsInvalid)."""
    httpx_mock.add_response(url=_ISSUER + "/token", json={"token_type": "Bearer"})
    with pytest.raises(OidcClaimsInvalid):
        exchange_code(
            token_endpoint=_ISSUER + "/token",
            code="c",
            redirect_uri=_REDIRECT_URI,
            client_id=_CLIENT_ID,
            client_secret=None,
            code_verifier="v",
        )


# --------------------------------------------------------------------------- #
# Pure helpers: _normalize_scope + _verify_id_token branches (no DB, no network).
# --------------------------------------------------------------------------- #
def test_normalize_scope_injects_openid_when_absent():
    """A scope string lacking 'openid' has it prepended (line 261)."""
    assert _normalize_scope("profile email").split()[0] == "openid"
    assert "profile" in _normalize_scope("profile email")
    # None -> just 'openid'.
    assert _normalize_scope(None) == "openid"
    # Already present -> unchanged ordering, single occurrence.
    assert _normalize_scope("openid profile").split().count("openid") == 1


def test_verify_id_token_iat_in_future_rejected():
    """An iat well in the future (beyond skew) -> OidcClaimsInvalid (line 380)."""
    priv, jwks = _gen_rsa()
    tok = _mint(priv, nonce="n0", iat=int(time.time()) + 3600)
    with pytest.raises(OidcClaimsInvalid):
        _verify_id_token(
            id_token=tok,
            jwks=jwks,
            issuer=_ISSUER,
            client_id=_CLIENT_ID,
            expected_nonce="n0",
            groups_claim="groups",
        )


def test_verify_id_token_missing_sub_rejected():
    """A token with an empty sub -> OidcClaimsInvalid (line 388)."""
    priv, jwks = _gen_rsa()
    tok = _mint(priv, nonce="n0", sub="")
    with pytest.raises(OidcClaimsInvalid):
        _verify_id_token(
            id_token=tok,
            jwks=jwks,
            issuer=_ISSUER,
            client_id=_CLIENT_ID,
            expected_nonce="n0",
            groups_claim="groups",
        )


def test_verify_id_token_scalar_groups_coerced_to_list():
    """A scalar (string) groups claim is coerced to a single-element list (line 392)."""
    priv, jwks = _gen_rsa()
    tok = _mint(priv, nonce="n0", groups="solo-group")
    sub, groups = _verify_id_token(
        id_token=tok,
        jwks=jwks,
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        expected_nonce="n0",
        groups_claim="groups",
    )
    assert sub == "operator-subject-1"
    assert groups == ["solo-group"]


def test_verify_id_token_non_list_groups_yields_empty():
    """A groups claim that is neither str nor list (e.g. an int) -> [] (line 396)."""
    priv, jwks = _gen_rsa()
    tok = _mint(priv, nonce="n0", groups=12345)
    _sub, groups = _verify_id_token(
        id_token=tok,
        jwks=jwks,
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        expected_nonce="n0",
        groups_claim="groups",
    )
    assert groups == []


# --------------------------------------------------------------------------- #
# DB-backed begin_login / complete_login edge branches. Offline stubs for the
# three network hooks; a real idp_config seed (skips cleanly when no DB).
# --------------------------------------------------------------------------- #
def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


async def _seed_tenant(*, with_config: bool, issuer: str = _ISSUER) -> str:
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB-backed OIDC edge test")
    tid = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"oidc-edge-{tid[:8]}"},
            )
            if with_config:
                await conn.execute(
                    text(
                        "INSERT INTO idp_config "
                        "(id, tenant_id, protocol, is_active, issuer, client_id, "
                        " client_secret_enc, scopes, sp_acs_url) "
                        "VALUES (:id, :t, 'oidc', true, :iss, :cid, :sec, :scopes, :acs)"
                    ),
                    {
                        "id": str(uuid.uuid4()),
                        "t": tid,
                        "iss": issuer,
                        "cid": _CLIENT_ID,
                        "sec": secret_box.encrypt("oidc-secret-" + uuid.uuid4().hex),
                        "scopes": "openid",
                        "acs": _REDIRECT_URI,
                    },
                )
    finally:
        await engine.dispose()
    return tid


async def _seed_incomplete_config() -> str:
    """A tenant + active OIDC config row that is MISSING issuer (incomplete)."""
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB-backed OIDC edge test")
    tid = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"oidc-inc-{tid[:8]}"},
            )
            await conn.execute(
                text(
                    "INSERT INTO idp_config "
                    "(id, tenant_id, protocol, is_active, client_id, sp_acs_url) "
                    "VALUES (:id, :t, 'oidc', true, :cid, :acs)"
                ),
                {"id": str(uuid.uuid4()), "t": tid, "cid": _CLIENT_ID, "acs": _REDIRECT_URI},
            )
    finally:
        await engine.dispose()
    return tid


async def _cleanup(tid: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM oidc_login_transaction WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


async def _stored_nonce(state: str) -> str:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            row = (
                await conn.execute(
                    text("SELECT nonce FROM oidc_login_transaction WHERE state = :s"),
                    {"s": state},
                )
            ).first()
            return row[0]
    finally:
        await engine.dispose()


async def test_begin_login_no_active_config_failclosed():
    """begin_login on a tenant with no active OIDC config -> OidcConfigUnavailable."""
    tid = await _seed_tenant(with_config=False)
    try:
        with pytest.raises(OidcConfigUnavailable):
            await begin_login(tid)
    finally:
        await _cleanup(tid)


async def test_begin_login_incomplete_config_failclosed():
    """begin_login on a config missing issuer -> OidcConfigUnavailable (incomplete)."""
    tid = await _seed_incomplete_config()
    try:
        with pytest.raises(OidcConfigUnavailable):
            await begin_login(tid)
    finally:
        await _cleanup(tid)


async def test_begin_login_discovery_missing_auth_endpoint(monkeypatch):
    """Discovery that omits authorization_endpoint -> OidcConfigUnavailable."""
    tid = await _seed_tenant(with_config=True)
    try:
        monkeypatch.setattr(
            oidc, "discover_oidc", lambda issuer: {"token_endpoint": f"{issuer}/token"}
        )
        with pytest.raises(OidcConfigUnavailable):
            await begin_login(tid)
    finally:
        await _cleanup(tid)


async def test_complete_login_discovery_missing_token_endpoint(monkeypatch):
    """At complete_login, discovery missing token/jwks endpoint -> OidcConfigUnavailable."""
    tid = await _seed_tenant(with_config=True)
    try:
        # begin_login needs a full discovery doc; complete_login then gets a
        # doc missing token_endpoint -> the 453-454 branch.
        monkeypatch.setattr(
            oidc,
            "discover_oidc",
            lambda issuer: {"authorization_endpoint": f"{issuer}/authorize"},
        )
        _auth, state = await begin_login(tid)
        with pytest.raises(OidcConfigUnavailable):
            await complete_login(state, "code")
    finally:
        await _cleanup(tid)


async def test_complete_login_config_disappeared_mid_flow(monkeypatch):
    """If the active config is deleted between begin and complete -> OidcConfigUnavailable."""
    tid = await _seed_tenant(with_config=True)
    try:
        monkeypatch.setattr(
            oidc,
            "discover_oidc",
            lambda issuer: {
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/token",
                "jwks_uri": f"{issuer}/jwks",
            },
        )
        _auth, state = await begin_login(tid)
        # Delete the config row (the transaction still exists) -> get_active raises
        # at complete_login's re-load step (lines 434-435).
        engine = _priv_engine()
        try:
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
        finally:
            await engine.dispose()
        with pytest.raises(OidcConfigUnavailable):
            await complete_login(state, "code")
    finally:
        await _cleanup(tid)
