"""SAML SSO login + ACS route tests (F-014 STEP 5, ADR-0017 §3/§6).

Drives the UNAUTHENTICATED sso_login_router (SAML half) through the real gateway app:
  - the routes are reachable WITHOUT an admin token (the /admin/sso prefix is exempt
    from AuthMiddleware/TenantContextMiddleware; require_admin is NOT on this router);
  - a tenant with no SAML config returns a uniform 404 sso_unavailable
    (anti-enumeration); a non-UUID tenant -> the same 404;
  - a full login->ACS with a mapped group returns the verified identity + role and
    NO operator session cookie (STEP-5 scope: no session minted yet);
  - an unmapped group -> 403 + operator_sso_denied (fail-closed, vector 14), no
    session;
  - an invalid assertion (forged/unknown RelayState request_id) -> generic 401, no
    session.

DB-backed; skips cleanly with no DB. The IdP is stubbed offline (RSA keypair + cert;
the assertion is signed with xmlsec). begin_login() issues a REAL AuthnRequest and
persists the single-use transaction, so the InResponseTo binding is exercised end to
end. Audit-committing tests use truncate_audit_log_after. SKIPS the module if
onelogin.saml2 is unavailable.
"""

from __future__ import annotations

import base64
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("onelogin.saml2")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from onelogin.saml2.constants import OneLogin_Saml2_Constants as _C  # noqa: E402
from onelogin.saml2.utils import OneLogin_Saml2_Utils  # noqa: E402
from sqlalchemy import select, text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from admin.sso import oidc_routes, secret_box  # noqa: E402
from persistence.models.events_audit_log import EventsAuditLog  # noqa: E402

pytestmark = pytest.mark.asyncio

_IDP_ENTITY = "https://idp.example.com/metadata"
_SP_AUDIENCE = "https://sp.example.com/saml/metadata"
_ACS = "https://sp.example.com/admin/sso/saml/acs"
_IDP_SSO_URL = "https://idp.example.com/sso"
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


def _gen_keypair_cert() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return priv, cert.public_bytes(serialization.Encoding.PEM).decode()


def _ts(delta_min: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_min)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _signed_response_b64(*, request_id: str, priv: str, cert: str, groups: str) -> str:
    """Build a Response carrying a single signed assertion for request_id."""
    aid = "_a" + uuid.uuid4().hex
    rid = "_r" + uuid.uuid4().hex
    iat = _ts(0)
    nb = _ts(-5)
    na = _ts(5)
    assertion = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{aid}" Version="2.0" IssueInstant="{iat}">'
        f"<saml:Issuer>{_IDP_ENTITY}</saml:Issuer>"
        f"<saml:Subject>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">'
        f"op-1</saml:NameID>"
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{na}" Recipient="{_ACS}" '
        f'InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">'
        f"<saml:AudienceRestriction><saml:Audience>{_SP_AUDIENCE}</saml:Audience>"
        f"</saml:AudienceRestriction></saml:Conditions>"
        f'<saml:AuthnStatement AuthnInstant="{iat}" SessionIndex="_s1">'
        f"<saml:AuthnContext><saml:AuthnContextClassRef>"
        f"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        f"</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
        f'<saml:AttributeStatement><saml:Attribute Name="groups" '
        f'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        f"<saml:AttributeValue>{groups}</saml:AttributeValue>"
        f"</saml:Attribute></saml:AttributeStatement></saml:Assertion>"
    )
    signed = OneLogin_Saml2_Utils.add_sign(
        assertion, priv, cert, sign_algorithm=_C.RSA_SHA256, digest_algorithm=_C.SHA256
    )
    if isinstance(signed, bytes):
        signed = signed.decode()
    xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" Version="2.0" '
        f'IssueInstant="{iat}" Destination="{_ACS}" InResponseTo="{request_id}">'
        f"<saml:Issuer>{_IDP_ENTITY}</saml:Issuer>"
        f"<samlp:Status><samlp:StatusCode "
        f'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f"{signed}</samlp:Response>"
    )
    return OneLogin_Saml2_Utils.b64encode(xml)


async def _seed(tid: str, cert_pem: str, *, with_config: bool = True) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"saml-{tid[:8]}"},
            )
            if with_config:
                await conn.execute(
                    text(
                        "INSERT INTO idp_config "
                        "(id, tenant_id, protocol, is_active, idp_entity_id, idp_sso_url, "
                        " idp_x509_cert, sp_acs_url, audience) "
                        "VALUES (:id, :t, 'saml', true, :ent, :sso, :cert, :acs, :aud)"
                    ),
                    {
                        "id": str(uuid.uuid4()),
                        "t": tid,
                        "ent": _IDP_ENTITY,
                        "sso": _IDP_SSO_URL,
                        "cert": cert_pem,
                        "acs": _ACS,
                        "aud": _SP_AUDIENCE,
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


async def _cleanup(tid: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM saml_login_transaction WHERE tenant_id = :t"), {"t": tid}
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
    oidc_routes.reset_rate_limit_for_testing()  # shared per-IP limiter
    yield
    secret_box.reset_key_cache_for_testing()
    oidc_routes.reset_rate_limit_for_testing()


@pytest.fixture()
def idp():
    priv, cert = _gen_keypair_cert()

    class _Idp:
        priv_pem = priv
        cert_pem = cert

    return _Idp()


# --------------------------------------------------------------------------- #
# Reachability without admin auth + anti-enumeration
# --------------------------------------------------------------------------- #
async def test_saml_login_unauthenticated_and_reachable(admin_app, idp):
    """/admin/sso/saml/login works with NO Authorization header and returns a
    redirect_url + request_id (router is not behind require_admin)."""
    tid = str(uuid.uuid4())
    await _seed(tid, idp.cert_pem)
    try:
        async with _client(admin_app) as client:
            r = await client.post("/admin/sso/saml/login", json={"tenant_id": tid})
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["redirect_url"].startswith(_IDP_SSO_URL)
            assert body["request_id"].startswith("ONELOGIN_")
    finally:
        await _cleanup(tid)


async def test_saml_login_no_config_uniform_404(admin_app, idp):
    """A tenant with no SAML config -> uniform 404 sso_unavailable (anti-enumeration)."""
    tid = str(uuid.uuid4())
    await _seed(tid, idp.cert_pem, with_config=False)
    try:
        async with _client(admin_app) as client:
            r = await client.post("/admin/sso/saml/login", json={"tenant_id": tid})
            assert r.status_code == 404
            assert r.json()["detail"] == "sso_unavailable"
    finally:
        await _cleanup(tid)


async def test_saml_login_non_uuid_tenant_uniform_404(admin_app):
    """A non-UUID tenant_id -> the SAME uniform 404 (no enumeration signal)."""
    async with _client(admin_app) as client:
        r = await client.post("/admin/sso/saml/login", json={"tenant_id": "not-a-uuid"})
        assert r.status_code == 404
        assert r.json()["detail"] == "sso_unavailable"


# --------------------------------------------------------------------------- #
# Full happy ACS (no operator session minted in STEP 5)
# --------------------------------------------------------------------------- #
async def test_saml_acs_success_returns_operator_session(
    admin_app, idp, truncate_audit_log_after, session
):
    """STEP-7: a mapped group -> provisioned principal + operator_sso_login row +
    a minted, tenant-pinned operator-session token returned to the caller. No PII
    (idp_subject) is echoed back (R6)."""
    from admin.sso.session import verify as verify_op

    tid = str(uuid.uuid4())
    await _seed(tid, idp.cert_pem)
    await _map_group(tid, "platform-admins", "tenant_admin")
    try:
        async with _client(admin_app) as client:
            rl = await client.post("/admin/sso/saml/login", json={"tenant_id": tid})
            request_id = rl.json()["request_id"]
            b64 = _signed_response_b64(
                request_id=request_id,
                priv=idp.priv_pem,
                cert=idp.cert_pem,
                groups="platform-admins",
            )
            rc = await client.post(
                "/admin/sso/saml/acs", json={"SAMLResponse": b64, "RelayState": request_id}
            )
            assert rc.status_code == 200, rc.text
            body = rc.json()
            assert body["tenant_id"] == tid
            assert body["role"] == "tenant_admin"
            assert body["token_type"] == "Bearer"  # noqa: S105 — response field, not a secret
            assert body["expires_in"] > 0
            token = body["operator_session_token"]
            assert token
            assert "idp_subject" not in body  # no PII to the browser (R6)
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
async def test_saml_acs_unmapped_group_denied(admin_app, idp, truncate_audit_log_after, session):
    tid = str(uuid.uuid4())
    await _seed(tid, idp.cert_pem)  # NO group mapping seeded
    try:
        async with _client(admin_app) as client:
            rl = await client.post("/admin/sso/saml/login", json={"tenant_id": tid})
            request_id = rl.json()["request_id"]
            b64 = _signed_response_b64(
                request_id=request_id, priv=idp.priv_pem, cert=idp.cert_pem, groups="unmapped"
            )
            rc = await client.post(
                "/admin/sso/saml/acs", json={"SAMLResponse": b64, "RelayState": request_id}
            )
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
# Forged/unknown RelayState request_id -> generic 401, no session
# --------------------------------------------------------------------------- #
async def test_saml_acs_forged_relaystate_generic_401(admin_app, idp):
    tid = str(uuid.uuid4())
    await _seed(tid, idp.cert_pem)
    try:
        # A response whose InResponseTo was never issued by us (IdP-initiated /
        # forged) -> single-use consume finds nothing -> generic 401.
        forged_rid = "ONELOGIN_" + uuid.uuid4().hex
        b64 = _signed_response_b64(
            request_id=forged_rid, priv=idp.priv_pem, cert=idp.cert_pem, groups="platform-admins"
        )
        async with _client(admin_app) as client:
            rc = await client.post(
                "/admin/sso/saml/acs", json={"SAMLResponse": b64, "RelayState": forged_rid}
            )
            assert rc.status_code == 401
            assert rc.json()["detail"] == "sso_authentication_failed"
            assert "set-cookie" not in {k.lower() for k in rc.headers}
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# MED 4 — build_settings fail-closes on a missing required field (no DB needed).
# --------------------------------------------------------------------------- #
def test_build_settings_rejects_missing_required_field():
    """build_settings raises SamlConfigUnavailable when a REQUIRED field
    (idp_entity_id / idp_sso_url / sp_acs_url) is empty/None instead of producing a
    strict settings dict with empty strings (F-014 code-review MED 4, fail-closed)."""
    from types import SimpleNamespace

    from admin.sso.saml import SamlConfigUnavailable, build_settings

    def _cfg(**over):
        base = dict(
            idp_entity_id=_IDP_ENTITY,
            idp_sso_url="https://idp.example.com/sso",
            idp_x509_cert="CERT",
            sp_acs_url=_ACS,
            audience=_SP_AUDIENCE,
        )
        base.update(over)
        return SimpleNamespace(**base)

    # Each required field individually empty/None -> raise (no half-built dict).
    for field in ("idp_entity_id", "idp_sso_url", "sp_acs_url"):
        with pytest.raises(SamlConfigUnavailable):
            build_settings(_cfg(**{field: None}))
        with pytest.raises(SamlConfigUnavailable):
            build_settings(_cfg(**{field: "   "}))  # whitespace-only is also empty

    # All required fields present -> builds a strict settings dict (sanity).
    settings = build_settings(_cfg())
    assert settings["strict"] is True
    assert settings["idp"]["entityId"] == _IDP_ENTITY
    assert settings["sp"]["assertionConsumerService"]["url"] == _ACS
