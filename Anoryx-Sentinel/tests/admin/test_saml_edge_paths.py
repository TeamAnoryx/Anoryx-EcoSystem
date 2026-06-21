"""SAML edge-path coverage (F-014 STEP 5, additive).

Companion to test_saml_threat_model.py. That suite drives complete_login() with
crafted responses; this file closes the remaining branches WITHOUT a live IdP:

  * _classify_errors is exercised directly for EVERY reason-code branch
    (signature/wrapping, unsigned, InResponseTo, time, conditions, default);
  * begin_login is run end-to-end (load config -> build settings -> AuthnRequest ->
    persist transaction -> redirect URL), plus its fail-closed branches
    (no active config, incomplete config);
  * complete_login edge branches: config-disappeared-mid-flow, a malformed
    SAMLResponse that makes process_response raise, a scalar groups attribute, and
    a missing groups attribute (-> []).

The IdP is stubbed FULLY OFFLINE (RSA keypair + self-signed cert + xmlsec signing
via python3-saml, mirroring test_saml_threat_model.py). No committed key/cert (R6).
SKIPS the module if onelogin.saml2 is unavailable; DB-backed tests skip when no DB.
"""

from __future__ import annotations

import base64
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("onelogin.saml2")  # degrade gracefully if the lib is absent

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from onelogin.saml2.constants import OneLogin_Saml2_Constants as _C  # noqa: E402
from onelogin.saml2.utils import OneLogin_Saml2_Utils  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from admin.sso import secret_box  # noqa: E402
from admin.sso.saml import (  # noqa: E402
    SamlConditionsInvalid,
    SamlConfigUnavailable,
    SamlReplay,
    SamlSignatureInvalid,
    SamlTimeInvalid,
    SamlUnsigned,
    VerifiedSamlIdentity,
    _classify_errors,
    begin_login,
    complete_login,
)

pytestmark = pytest.mark.asyncio

_IDP_ENTITY = "https://idp.example.com/metadata"
_SP_AUDIENCE = "https://sp.example.com/saml/metadata"
_ACS = "https://sp.example.com/admin/sso/saml/acs"
_IDP_SSO_URL = "https://idp.example.com/sso"
_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


# --------------------------------------------------------------------------- #
# _classify_errors — pure mapping of every reason-code branch (no DB, no XML).
# --------------------------------------------------------------------------- #
def test_classify_errors_signature_wrapping():
    """A wrapping/signature reason maps to SamlSignatureInvalid (line 353)."""
    assert isinstance(
        _classify_errors(["invalid_response"], "Signature validation failed"),
        SamlSignatureInvalid,
    )
    assert isinstance(
        _classify_errors(["invalid_response"], "found multiple node signature wrapping"),
        SamlSignatureInvalid,
    )


def test_classify_errors_unsigned():
    """An 'not signed' / 'require it' reason maps to SamlUnsigned (line 355)."""
    assert isinstance(
        _classify_errors(["invalid_response"], "The assertion is not signed"),
        SamlUnsigned,
    )


def test_classify_errors_inresponseto():
    """An InResponseTo/unsolicited reason maps to SamlReplay (line 357)."""
    assert isinstance(
        _classify_errors(["invalid_response"], "The InResponseTo of the Response mismatch"),
        SamlReplay,
    )
    assert isinstance(
        _classify_errors(["invalid_response"], "rejecting unsolicited response"),
        SamlReplay,
    )


def test_classify_errors_time():
    """A timestamp/expired reason maps to SamlTimeInvalid (line 364)."""
    assert isinstance(
        _classify_errors(["invalid_response"], "Could not validate timestamp: expired"),
        SamlTimeInvalid,
    )
    assert isinstance(
        _classify_errors(["invalid_response"], "Assertion is not yet valid"),
        SamlTimeInvalid,
    )


def test_classify_errors_conditions():
    """An issuer/audience/recipient/destination reason -> SamlConditionsInvalid (line 373)."""
    for reason in (
        "Invalid audience for this Response",
        "Invalid issuer in the Assertion/Response",
        "The recipient of the Response does not match",
        "The response was received at a different destination",
        "No SubjectConfirmation passed criteria",
    ):
        assert isinstance(
            _classify_errors(["invalid_response"], reason), SamlConditionsInvalid
        ), reason


def test_classify_errors_default_is_signature_invalid():
    """An unclassified reason falls back to SamlSignatureInvalid (line 375, fail-closed)."""
    assert isinstance(
        _classify_errors(["invalid_response"], "something totally unexpected"),
        SamlSignatureInvalid,
    )
    # None last_reason also classified (default).
    assert isinstance(_classify_errors([], None), SamlSignatureInvalid)


# --------------------------------------------------------------------------- #
# Offline IdP stub (RSA keypair + cert + signed assertions).
# --------------------------------------------------------------------------- #
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


def _assertion_xml(
    *, request_id: str, groups_attr: str = "groups", group_value: str = "platform-admins"
) -> str:
    aid = "_a" + uuid.uuid4().hex
    iat = _ts(0)
    nb = _ts(-5)
    na = _ts(5)
    attr_stmt = (
        f'<saml:AttributeStatement><saml:Attribute Name="{groups_attr}" '
        f'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        f"<saml:AttributeValue>{group_value}</saml:AttributeValue>"
        f"</saml:Attribute></saml:AttributeStatement>"
    )
    return (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{aid}" Version="2.0" IssueInstant="{iat}">'
        f"<saml:Issuer>{_IDP_ENTITY}</saml:Issuer>"
        f"<saml:Subject>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">'
        f"operator-subject-1</saml:NameID>"
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
        f"{attr_stmt}</saml:Assertion>"
    )


def _sign(assertion_xml: str, priv: str, cert: str) -> str:
    signed = OneLogin_Saml2_Utils.add_sign(
        assertion_xml, priv, cert, sign_algorithm=_C.RSA_SHA256, digest_algorithm=_C.SHA256
    )
    return signed.decode() if isinstance(signed, bytes) else signed


def _response_b64(*, inner: str, request_id: str) -> str:
    rid = "_r" + uuid.uuid4().hex
    iat = _ts(0)
    xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" Version="2.0" '
        f'IssueInstant="{iat}" Destination="{_ACS}" InResponseTo="{request_id}">'
        f"<saml:Issuer>{_IDP_ENTITY}</saml:Issuer>"
        f"<samlp:Status><samlp:StatusCode "
        f'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f"{inner}</samlp:Response>"
    )
    return OneLogin_Saml2_Utils.b64encode(xml)


# --------------------------------------------------------------------------- #
# DB seed/cleanup (privileged connection).
# --------------------------------------------------------------------------- #
def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


async def _seed_tenant_and_config(cert_pem: str, *, complete: bool = True) -> str:
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB-backed SAML edge test")
    tid = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"saml-edge-{tid[:8]}"},
            )
            if complete:
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
            else:
                # Active config row MISSING idp_sso_url + idp_entity_id (incomplete).
                await conn.execute(
                    text(
                        "INSERT INTO idp_config "
                        "(id, tenant_id, protocol, is_active, sp_acs_url) "
                        "VALUES (:id, :t, 'saml', true, :acs)"
                    ),
                    {"id": str(uuid.uuid4()), "t": tid, "acs": _ACS},
                )
    finally:
        await engine.dispose()
    return tid


async def _seed_tenant_no_config() -> str:
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB-backed SAML edge test")
    tid = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"saml-noc-{tid[:8]}"},
            )
    finally:
        await engine.dispose()
    return tid


async def _seed_request(tid: str, request_id: str) -> None:
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO saml_login_transaction "
                    "(request_id, tenant_id, idp_config_id, expires_at) "
                    "VALUES (:rid, :t, :cid, now() + interval '300 seconds')"
                ),
                {"rid": request_id, "t": tid, "cid": str(uuid.uuid4())},
            )
    finally:
        await engine.dispose()


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
                text("DELETE FROM saml_login_transaction WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(
                text("DELETE FROM idp_group_role_map WHERE tenant_id = :t"), {"t": tid}
            )
            await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
    finally:
        await engine.dispose()


def _new_request_id() -> str:
    return "ONELOGIN_" + uuid.uuid4().hex


@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, base64.b64encode(os.urandom(32)).decode("ascii"))
    yield
    secret_box.reset_key_cache_for_testing()


@pytest.fixture()
def idp():
    priv, cert = _gen_keypair_cert()

    class _Idp:
        priv_pem = priv
        cert_pem = cert

    return _Idp()


# --------------------------------------------------------------------------- #
# begin_login — happy path (load -> build -> AuthnRequest -> persist -> redirect)
# plus fail-closed branches.
# --------------------------------------------------------------------------- #
async def test_begin_login_returns_redirect_and_request_id(idp):
    """begin_login loads config, issues an AuthnRequest, persists the transaction,
    and returns the IdP redirect URL + the generated request id (lines 291-330)."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    try:
        redirect_url, request_id = await begin_login(tid)
        assert redirect_url.startswith(_IDP_SSO_URL)
        assert "SAMLRequest=" in redirect_url
        assert request_id
        # The single-use transaction was persisted for that request_id.
        engine = _priv_engine()
        try:
            async with engine.begin() as conn:
                row = (
                    await conn.execute(
                        text(
                            "SELECT tenant_id FROM saml_login_transaction "
                            "WHERE request_id = :rid"
                        ),
                        {"rid": request_id},
                    )
                ).first()
                assert row is not None and row[0] == tid
        finally:
            await engine.dispose()
    finally:
        await _cleanup(tid)


async def test_begin_login_no_active_config_failclosed():
    """begin_login with no active SAML config -> SamlConfigUnavailable (line 296-297)."""
    tid = await _seed_tenant_no_config()
    try:
        with pytest.raises(SamlConfigUnavailable):
            await begin_login(tid)
    finally:
        await _cleanup(tid)


async def test_begin_login_incomplete_config_failclosed():
    """begin_login with an incomplete config (missing idp fields) -> SamlConfigUnavailable.

    build_settings raises on the missing required field(s) up front (fail-closed)."""
    tid = await _seed_tenant_and_config("", complete=False)
    try:
        with pytest.raises(SamlConfigUnavailable):
            await begin_login(tid)
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# complete_login edge branches.
# --------------------------------------------------------------------------- #
async def test_complete_login_config_disappeared_mid_flow(idp):
    """If the config is deleted after the transaction is seeded -> SamlConfigUnavailable
    at the re-load step (lines 412-413)."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        # Delete the config row only (transaction remains) so complete_login's
        # re-load raises IdpConfigNotFoundError -> SamlConfigUnavailable.
        engine = _priv_engine()
        try:
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tid})
        finally:
            await engine.dispose()
        signed = _sign(_assertion_xml(request_id=rid), idp.priv_pem, idp.cert_pem)
        b64 = _response_b64(inner=signed, request_id=rid)
        with pytest.raises(SamlConfigUnavailable):
            await complete_login(b64, rid)
    finally:
        await _cleanup(tid)


async def test_complete_login_malformed_response_failclosed(idp):
    """A SAMLResponse that is not valid base64 XML makes process_response raise ->
    SamlSignatureInvalid (the typed fail-closed wrapper, lines 432-434)."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        garbage = base64.b64encode(b"this-is-not-saml-xml").decode("ascii")
        with pytest.raises(SamlSignatureInvalid):
            await complete_login(garbage, rid)
    finally:
        await _cleanup(tid)


async def test_complete_login_scalar_groups_attribute(idp):
    """A groups attribute carrying a single value is coerced to a one-element list.

    (python3-saml returns attribute values as a list, so this asserts the happy
    path groups extraction and the str-coercion path.)"""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    await _seed_group_mapping(tid, "platform-admins", "tenant_admin")
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        signed = _sign(
            _assertion_xml(request_id=rid, group_value="platform-admins"),
            idp.priv_pem,
            idp.cert_pem,
        )
        b64 = _response_b64(inner=signed, request_id=rid)
        identity = await complete_login(b64, rid)
        assert isinstance(identity, VerifiedSamlIdentity)
        assert identity.groups == ["platform-admins"]
    finally:
        await _cleanup(tid)


async def test_complete_login_missing_groups_attribute_yields_empty(idp):
    """An assertion whose AttributeStatement carries NO 'groups' attribute yields an
    empty groups list (the attributes.get default -> []).

    The assertion still carries an AttributeStatement (python3-saml's
    wantAttributeStatement default is True), but under a different attribute name,
    so the configured 'groups' attribute is absent. Fail-closed at group->role
    resolution downstream, never silently granted."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        signed = _sign(
            # An attribute named "department" — the configured "groups" attr is absent.
            _assertion_xml(request_id=rid, groups_attr="department", group_value="eng"),
            idp.priv_pem,
            idp.cert_pem,
        )
        b64 = _response_b64(inner=signed, request_id=rid)
        identity = await complete_login(b64, rid)
        assert isinstance(identity, VerifiedSamlIdentity)
        assert identity.groups == []
    finally:
        await _cleanup(tid)
