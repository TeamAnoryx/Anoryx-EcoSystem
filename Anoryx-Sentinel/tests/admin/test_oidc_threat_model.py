"""OIDC threat-model tests (F-014 STEP 4, ADR-0017 §5 / §12 vectors 9-13 + 2).

Each rejection test proves the attack FAILS — asserting the correct rejection AND
that NO verified identity / operator session is produced (fail-closed, R4). The IdP
is stubbed FULLY OFFLINE: an RSA keypair is generated at runtime, a JWKS dict is
built from it, and ID tokens are minted with authlib's signer. The three outbound
calls in admin.sso.oidc (discover_oidc, fetch_jwks, exchange_code) are monkeypatched
so no network is touched and no secret/key is committed (R6, F-005 push-protection
lesson).

Vectors covered here:
  9  — state mismatch / unknown forged state -> rejected.
  10 — nonce replay: a completed flow's state replayed -> rejected (single-use);
       a token whose nonce != stored -> rejected.
  11 — ID token signed by a DIFFERENT key than the JWKS -> rejected.
  12 — wrong iss, wrong aud, expired exp each -> rejected.
  13 — token exchange that omits/!=code_verifier -> rejected (verifier IS sent +
       required).
  2  — tenant binding: the returned tenant is the idp_config OWNER, never a
       token-supplied value.
  +  happy path: begin->complete with a correctly-signed token + mapped group ->
     verified identity with the resolved role.

DB-backed (idp_config + the oidc_login_transaction store live in Postgres). Skips
cleanly when no DB is configured. Audit-committing tests use truncate_audit_log_after
so the global hash chain is not polluted.
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
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from admin.sso import oidc, secret_box
from admin.sso.oidc import (
    OidcClaimsInvalid,
    OidcPkceInvalid,
    OidcReplay,
    OidcSignatureInvalid,
    OidcStateInvalid,
    VerifiedOidcIdentity,
    begin_login,
    complete_login,
)

pytestmark = pytest.mark.asyncio

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "client-abc"
_REDIRECT_URI = "https://sp.example.com/admin/sso/oidc/callback"
_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


# --------------------------------------------------------------------------- #
# Offline IdP stub: RSA keypair -> JWKS -> minted ID tokens.
# --------------------------------------------------------------------------- #
def _gen_rsa() -> tuple[bytes, bytes, dict]:
    """Return (private_pem, public_pem, jwks_dict) for a fresh RSA keypair."""
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
    return priv_pem, pub_pem, {"keys": [jwk]}


def _mint_id_token(priv_pem: bytes, **claim_overrides) -> str:
    """Mint an RS256 ID token with sensible defaults, overridable per test."""
    now = int(time.time())
    claims = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": "operator-subject-1",
        "exp": now + 300,
        "iat": now,
        "nonce": "REPLACED_PER_FLOW",
        "groups": ["platform-admins"],
    }
    claims.update(claim_overrides)
    jwt = JsonWebToken(["RS256"])
    return jwt.encode({"alg": "RS256", "kid": "test-kid"}, claims, priv_pem)


def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    url = _to_asyncpg(os.environ["DATABASE_URL"])
    return create_async_engine(
        url, connect_args={"server_settings": {"app.session_kind": "privileged"}}
    )


async def _seed_tenant_and_config() -> str:
    """Commit a tenant + active OIDC idp_config; return tenant_id."""
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB-backed OIDC test")
    tid = str(uuid.uuid4())
    secret_blob = secret_box.encrypt("oidc-client-secret-" + uuid.uuid4().hex)
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"oidc-{tid[:8]}"},
            )
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
                    "iss": _ISSUER,
                    "cid": _CLIENT_ID,
                    "sec": secret_blob,
                    "scopes": "openid profile groups",
                    "acs": _REDIRECT_URI,
                },
            )
    finally:
        await engine.dispose()
    return tid


async def _seed_group_mapping(tid: str, group: str, role: str) -> None:
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
                text("DELETE FROM oidc_login_transaction WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(
                text("DELETE FROM idp_group_role_map WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


async def _stored_nonce_for_state(state: str) -> str:
    """Read back the server-side nonce for a state (to mint a matching token)."""
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


@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    """Provide an ephemeral IdP-secret encryption key; reset the cache per test."""
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, base64.b64encode(os.urandom(32)).decode("ascii"))
    yield
    secret_box.reset_key_cache_for_testing()


@pytest.fixture()
def idp(monkeypatch):
    """Wire the offline IdP: keypair + JWKS + monkeypatched discovery/jwks/exchange.

    Returns a small object exposing the priv key (to mint tokens) and a mutable
    `token_to_return` the stubbed exchange_code hands back. `captured` records the
    args the token exchange was called with (to assert the PKCE verifier was sent).
    """
    priv_pem, _pub_pem, jwks = _gen_rsa()

    state = {"token": None, "captured": {}}

    def _discover(issuer: str) -> dict:
        return {
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
        }

    def _fetch_jwks(jwks_uri: str) -> dict:
        return jwks

    def _exchange(*, token_endpoint, code, redirect_uri, client_id, client_secret, code_verifier):
        state["captured"] = {
            "code": code,
            "code_verifier": code_verifier,
            "client_id": client_id,
        }
        # Simulate a PKCE-enforcing IdP: reject if no verifier was sent.
        if not code_verifier:
            from admin.sso.oidc import OidcPkceInvalid as _Pkce

            raise _Pkce("missing code_verifier")
        return {"id_token": state["token"], "token_type": "Bearer"}

    monkeypatch.setattr(oidc, "discover_oidc", _discover)
    monkeypatch.setattr(oidc, "fetch_jwks", _fetch_jwks)
    monkeypatch.setattr(oidc, "exchange_code", _exchange)

    class _Idp:
        priv = priv_pem
        jwks_doc = jwks

        @staticmethod
        def set_token(tok: str) -> None:
            state["token"] = tok

        @staticmethod
        def captured() -> dict:
            return state["captured"]

    return _Idp()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
async def test_oidc_happy_path_returns_identity_and_role(idp):
    """begin->complete with a correctly-signed token + mapped group -> identity+role."""
    tid = await _seed_tenant_and_config()
    await _seed_group_mapping(tid, "platform-admins", "tenant_admin")
    try:
        auth_url, state = await begin_login(tid)
        assert "code_challenge=" in auth_url and "code_challenge_method=S256" in auth_url
        assert f"state={state}" in auth_url

        nonce = await _stored_nonce_for_state(state)
        idp.set_token(_mint_id_token(idp.priv, nonce=nonce, groups=["platform-admins"]))

        identity = await complete_login(state, "auth-code-xyz")
        assert isinstance(identity, VerifiedOidcIdentity)
        assert identity.tenant_id == tid  # R1: idp_config owner
        assert identity.idp_subject == "operator-subject-1"
        assert identity.groups == ["platform-admins"]
        # The PKCE verifier WAS sent at exchange (vector 13 positive control).
        assert idp.captured()["code_verifier"]
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 9 — state mismatch / unknown forged state
# --------------------------------------------------------------------------- #
async def test_oidc_state_mismatch_rejected(idp):
    """A callback with an unknown/forged state -> rejected (OidcStateInvalid)."""
    tid = await _seed_tenant_and_config()
    try:
        await begin_login(tid)  # creates a real state we do NOT use
        idp.set_token(_mint_id_token(idp.priv, nonce="whatever"))
        with pytest.raises(OidcStateInvalid):
            await complete_login("forged-state-never-issued", "auth-code")
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 10 — nonce replay (single-use state) + nonce mismatch
# --------------------------------------------------------------------------- #
async def test_oidc_nonce_replay_rejected(idp):
    """A completed flow's state cannot be replayed; a wrong-nonce token is rejected."""
    tid = await _seed_tenant_and_config()
    await _seed_group_mapping(tid, "platform-admins", "tenant_admin")
    try:
        # (a) single-use: complete once, then replay the SAME state -> rejected.
        _auth, state = await begin_login(tid)
        nonce = await _stored_nonce_for_state(state)
        idp.set_token(_mint_id_token(idp.priv, nonce=nonce))
        first = await complete_login(state, "code-1")
        assert isinstance(first, VerifiedOidcIdentity)
        with pytest.raises(OidcStateInvalid):
            await complete_login(state, "code-1")  # replay of consumed state

        # (b) nonce mismatch: fresh flow, token carries a DIFFERENT nonce -> rejected.
        _auth2, state2 = await begin_login(tid)
        idp.set_token(_mint_id_token(idp.priv, nonce="not-the-stored-nonce"))
        with pytest.raises(OidcReplay):
            await complete_login(state2, "code-2")
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 11 — token signed by a different key than the JWKS
# --------------------------------------------------------------------------- #
async def test_oidc_bad_signature_rejected(idp):
    """An ID token signed by a DIFFERENT key than the JWKS -> rejected."""
    tid = await _seed_tenant_and_config()
    try:
        _auth, state = await begin_login(tid)
        nonce = await _stored_nonce_for_state(state)
        # Mint with a FOREIGN private key (not the one in the served JWKS).
        foreign_priv, _pub, _jwks = _gen_rsa()
        idp.set_token(_mint_id_token(foreign_priv, nonce=nonce))
        with pytest.raises(OidcSignatureInvalid):
            await complete_login(state, "code")
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 12 — iss / aud / exp validation
# --------------------------------------------------------------------------- #
async def test_oidc_iss_aud_exp_validated(idp):
    """Wrong iss, wrong aud, and an expired exp each -> rejected (OidcClaimsInvalid)."""
    tid = await _seed_tenant_and_config()
    try:
        # Wrong iss.
        _a, s1 = await begin_login(tid)
        n1 = await _stored_nonce_for_state(s1)
        idp.set_token(_mint_id_token(idp.priv, nonce=n1, iss="https://evil.example.com"))
        with pytest.raises(OidcClaimsInvalid):
            await complete_login(s1, "c1")

        # Wrong aud.
        _b, s2 = await begin_login(tid)
        n2 = await _stored_nonce_for_state(s2)
        idp.set_token(_mint_id_token(idp.priv, nonce=n2, aud="some-other-client"))
        with pytest.raises(OidcClaimsInvalid):
            await complete_login(s2, "c2")

        # Expired exp (well beyond the skew).
        _c, s3 = await begin_login(tid)
        n3 = await _stored_nonce_for_state(s3)
        idp.set_token(_mint_id_token(idp.priv, nonce=n3, exp=int(time.time()) - 3600))
        with pytest.raises(OidcClaimsInvalid):
            await complete_login(s3, "c3")
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 13 — PKCE enforced (verifier sent + required)
# --------------------------------------------------------------------------- #
async def test_oidc_pkce_enforced(monkeypatch, idp):
    """The PKCE verifier is sent at exchange; an IdP that requires it and gets none
    -> rejected. Positive: the real flow always sends a non-empty verifier."""
    tid = await _seed_tenant_and_config()
    try:
        _auth, state = await begin_login(tid)
        nonce = await _stored_nonce_for_state(state)
        idp.set_token(_mint_id_token(idp.priv, nonce=nonce))

        # Positive control: the verifier IS sent (captured by the stub).
        identity = await complete_login(state, "code-ok")
        assert isinstance(identity, VerifiedOidcIdentity)
        assert idp.captured()["code_verifier"], "PKCE verifier must be sent at exchange"

        # Negative: a token endpoint that rejects (e.g. wrong/absent verifier)
        # surfaces as OidcPkceInvalid (the exchange raised). Simulate by replacing
        # exchange_code with one that always rejects.
        def _reject_exchange(**_kwargs):
            raise OidcPkceInvalid("pkce verification failed")

        monkeypatch.setattr(oidc, "exchange_code", _reject_exchange)
        _auth2, state2 = await begin_login(tid)
        with pytest.raises(OidcPkceInvalid):
            await complete_login(state2, "code-bad-verifier")
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 2 — tenant binding (owner, never the token)
# --------------------------------------------------------------------------- #
async def test_oidc_login_tenant_binding(idp):
    """The returned tenant is the idp_config OWNER; a token claiming a different
    tenant does NOT change it (R1, vector 2)."""
    tid = await _seed_tenant_and_config()
    await _seed_group_mapping(tid, "platform-admins", "tenant_admin")
    other_tenant = str(uuid.uuid4())
    try:
        _auth, state = await begin_login(tid)
        nonce = await _stored_nonce_for_state(state)
        # The token tries to assert a different tenant via custom claims — ignored.
        idp.set_token(
            _mint_id_token(
                idp.priv,
                nonce=nonce,
                tenant_id=other_tenant,  # attacker-supplied claim
                tid=other_tenant,  # alternate spelling
            )
        )
        identity = await complete_login(state, "code")
        assert identity.tenant_id == tid  # owner, NOT the token's tenant claim
        assert identity.tenant_id != other_tenant
    finally:
        await _cleanup(tid)
