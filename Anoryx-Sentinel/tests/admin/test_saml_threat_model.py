"""SAML threat-model tests (F-014 STEP 5, ADR-0017 §6 / §12 vectors 4-8 + 2).

Each rejection test proves the attack FAILS — asserting the correct rejection AND
that NO verified identity (no operator NameID/role) is produced (fail-closed, R4).
The IdP is stubbed FULLY OFFLINE: an RSA keypair + self-signed cert is generated at
runtime, SAMLResponse XML is built, and the ASSERTION is signed with xmlsec via
python3-saml's OneLogin_Saml2_Utils.add_sign (no network, no committed key/cert —
R6, F-005 push-protection lesson). complete_login() is driven directly; the
single-use saml_login_transaction is seeded via the privileged store so the
InResponseTo binding is exercised end-to-end.

Vectors covered here:
  4 — signature wrapping (XSW): a forged unsigned assertion wrapped alongside the
      legitimately-signed one -> rejected; the identity is NOT the attacker's.
  5 — unsigned assertion -> rejected (wantAssertionsSigned).
  6 — NotOnOrAfter in the past, and NotBefore in the future -> each rejected.
  7 — replay (same InResponseTo consumed twice) -> rejected; an unknown/absent
      InResponseTo (IdP-initiated) -> rejected.
  8 — Recipient/Destination != our ACS -> rejected.
  2 — wrong Audience / wrong Issuer -> rejected; the returned tenant is the
      idp_config OWNER, never an assertion value.
  +  happy path: a correctly-signed assertion with valid conditions + matching
     InResponseTo + a mapped group -> identity with the resolved role.

python3-saml does the XML signature validation (R3); these tests prove our STRICT
configuration + condition checks reject every vector. SKIPS the whole module if
onelogin.saml2 is unavailable, and skips individual DB-backed tests when no DB.
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
    SamlReplay,
    SamlSignatureInvalid,
    SamlTimeInvalid,
    SamlUnsigned,
    VerifiedSamlIdentity,
    complete_login,
)
from persistence.repositories.idp_group_role_map_repository import (  # noqa: E402
    IdpGroupRoleMapRepository,
)

pytestmark = pytest.mark.asyncio

_IDP_ENTITY = "https://idp.example.com/metadata"
_SP_AUDIENCE = "https://sp.example.com/saml/metadata"
_ACS = "https://sp.example.com/admin/sso/saml/acs"
_IDP_SSO_URL = "https://idp.example.com/sso"
_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"
_TTL = 300


# --------------------------------------------------------------------------- #
# Offline IdP stub: RSA keypair + self-signed cert -> signed assertions.
# --------------------------------------------------------------------------- #
def _gen_keypair_cert() -> tuple[str, str]:
    """Return (private_pem, cert_pem) for a fresh RSA keypair + self-signed cert."""
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
    *,
    request_id: str,
    subject: str = "operator-subject-1",
    audience: str = _SP_AUDIENCE,
    issuer: str = _IDP_ENTITY,
    recipient: str = _ACS,
    not_before_min: int = -5,
    not_on_or_after_min: int = 5,
    groups: str = "platform-admins",
) -> str:
    """Build a single <saml:Assertion> XML string (signed separately by the caller)."""
    aid = "_a" + uuid.uuid4().hex
    iat = _ts(0)
    nb = _ts(not_before_min)
    na = _ts(not_on_or_after_min)
    return (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{aid}" Version="2.0" IssueInstant="{iat}">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f"<saml:Subject>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">'
        f"{subject}</saml:NameID>"
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{na}" Recipient="{recipient}" '
        f'InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">'
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
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


def _sign(assertion_xml: str, priv: str, cert: str) -> str:
    """Sign the assertion node with xmlsec (RSA-SHA256), via python3-saml's add_sign."""
    signed = OneLogin_Saml2_Utils.add_sign(
        assertion_xml,
        priv,
        cert,
        sign_algorithm=_C.RSA_SHA256,
        digest_algorithm=_C.SHA256,
    )
    return signed.decode() if isinstance(signed, bytes) else signed


def _response_b64(
    *, inner: str, request_id: str, destination: str = _ACS, issuer: str = _IDP_ENTITY
) -> str:
    """Wrap one-or-more assertion fragments in a <samlp:Response> and base64-encode."""
    rid = "_r" + uuid.uuid4().hex
    iat = _ts(0)
    xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" Version="2.0" '
        f'IssueInstant="{iat}" Destination="{destination}" InResponseTo="{request_id}">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f"<samlp:Status><samlp:StatusCode "
        f'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f"{inner}</samlp:Response>"
    )
    return OneLogin_Saml2_Utils.b64encode(xml)


# --------------------------------------------------------------------------- #
# DB seed/cleanup helpers (privileged connection).
# --------------------------------------------------------------------------- #
def _to_asyncpg(raw: str) -> str:
    return re.sub(r"^postgresql(?:\+psycopg)?://", "postgresql+asyncpg://", raw)


def _priv_engine():
    return create_async_engine(
        _to_asyncpg(os.environ["DATABASE_URL"]),
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


async def _seed_tenant_and_config(cert_pem: str) -> str:
    """Commit a tenant + active SAML idp_config; return tenant_id."""
    if not os.environ.get("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set — skipping DB-backed SAML test")
    tid = str(uuid.uuid4())
    engine = _priv_engine()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (tenant_id, name, is_active) VALUES (:t, :n, true)"),
                {"t": tid, "n": f"saml-{tid[:8]}"},
            )
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
    return tid


async def _seed_request(tid: str, request_id: str) -> None:
    """Insert a live (unconsumed) saml_login_transaction for request_id."""
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
    """Provide an ephemeral IdP-secret encryption key; reset the cache per test."""
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, base64.b64encode(os.urandom(32)).decode("ascii"))
    yield
    secret_box.reset_key_cache_for_testing()


@pytest.fixture()
def idp():
    """A fresh offline IdP keypair + cert for the test."""
    priv, cert = _gen_keypair_cert()

    class _Idp:
        priv_pem = priv
        cert_pem = cert

    return _Idp()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
async def test_saml_happy_path_returns_identity_and_role(idp):
    """A correctly-signed assertion + valid conditions + matching InResponseTo +
    a mapped group -> verified identity with the resolved role."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    await _seed_group_mapping(tid, "platform-admins", "tenant_admin")
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        signed = _sign(_assertion_xml(request_id=rid), idp.priv_pem, idp.cert_pem)
        b64 = _response_b64(inner=signed, request_id=rid)

        identity = await complete_login(b64, rid)
        assert isinstance(identity, VerifiedSamlIdentity)
        assert identity.tenant_id == tid  # R1: idp_config owner
        assert identity.idp_subject == "operator-subject-1"
        assert identity.groups == ["platform-admins"]

        # group->role resolution (mirrors the ACS route) yields the mapped role.
        from persistence.database import get_tenant_session

        async with get_tenant_session(tid) as ts:
            role = await IdpGroupRoleMapRepository(ts).resolve_role(
                tenant_id=tid, groups=identity.groups, caller_tenant_id=tid
            )
        assert role == "tenant_admin"
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 4 — signature wrapping (XSW)
# --------------------------------------------------------------------------- #
async def test_saml_signature_wrapping_rejected(idp):
    """XSW: a forged UNSIGNED assertion wrapped alongside the legitimately-signed
    one -> rejected. The verified identity is NOT the attacker's injected subject."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        legit_signed = _sign(
            _assertion_xml(request_id=rid, subject="operator-subject-1"),
            idp.priv_pem,
            idp.cert_pem,
        )
        # The attacker's forged, UNSIGNED assertion claiming an injected subject.
        forged = _assertion_xml(request_id=rid, subject="attacker-injected")
        # Wrap BOTH into one Response (forged first, then the legit signed one).
        b64 = _response_b64(inner=forged + legit_signed, request_id=rid)

        with pytest.raises(SamlSignatureInvalid):
            await complete_login(b64, rid)
        # Belt-and-braces: nothing usable was produced (no identity object exists).
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 5 — unsigned assertion
# --------------------------------------------------------------------------- #
async def test_saml_unsigned_assertion_rejected(idp):
    """An assertion with NO signature -> rejected (wantAssertionsSigned)."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    rid = _new_request_id()
    await _seed_request(tid, rid)
    try:
        unsigned = _assertion_xml(request_id=rid)  # never signed
        b64 = _response_b64(inner=unsigned, request_id=rid)
        with pytest.raises((SamlUnsigned, SamlSignatureInvalid)):
            await complete_login(b64, rid)
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 6 — expired / NotBefore-in-the-future
# --------------------------------------------------------------------------- #
async def test_saml_expired_or_notbefore_rejected(idp):
    """NotOnOrAfter in the past, and NotBefore in the future, each -> rejected."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    try:
        # (a) Expired: NotOnOrAfter well in the past.
        rid1 = _new_request_id()
        await _seed_request(tid, rid1)
        expired = _sign(
            _assertion_xml(request_id=rid1, not_before_min=-120, not_on_or_after_min=-60),
            idp.priv_pem,
            idp.cert_pem,
        )
        with pytest.raises(SamlTimeInvalid):
            await complete_login(_response_b64(inner=expired, request_id=rid1), rid1)

        # (b) NotBefore in the future (not yet valid).
        rid2 = _new_request_id()
        await _seed_request(tid, rid2)
        future = _sign(
            _assertion_xml(request_id=rid2, not_before_min=60, not_on_or_after_min=120),
            idp.priv_pem,
            idp.cert_pem,
        )
        with pytest.raises(SamlTimeInvalid):
            await complete_login(_response_b64(inner=future, request_id=rid2), rid2)
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 7 — replay / unknown-or-absent InResponseTo
# --------------------------------------------------------------------------- #
async def test_saml_replay_rejected(idp):
    """A valid response consumed once, replayed (same InResponseTo) -> rejected
    (single-use). A response whose InResponseTo is unknown (IdP-initiated) ->
    rejected."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    try:
        # (a) single-use: complete once, then replay the SAME response -> rejected.
        rid = _new_request_id()
        await _seed_request(tid, rid)
        signed = _sign(_assertion_xml(request_id=rid), idp.priv_pem, idp.cert_pem)
        b64 = _response_b64(inner=signed, request_id=rid)
        first = await complete_login(b64, rid)
        assert isinstance(first, VerifiedSamlIdentity)
        with pytest.raises(SamlReplay):
            await complete_login(b64, rid)  # replay of the consumed request_id

        # (b) unknown / unsolicited InResponseTo (IdP-initiated injection): a
        # request_id for which NO transaction was ever issued -> rejected.
        unknown_rid = _new_request_id()
        signed2 = _sign(_assertion_xml(request_id=unknown_rid), idp.priv_pem, idp.cert_pem)
        b64_2 = _response_b64(inner=signed2, request_id=unknown_rid)
        with pytest.raises(SamlReplay):
            await complete_login(b64_2, unknown_rid)
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 8 — wrong Recipient/Destination
# --------------------------------------------------------------------------- #
async def test_saml_wrong_recipient_destination_rejected(idp):
    """Recipient/Destination != our ACS -> rejected."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    try:
        # (a) wrong Recipient inside the signed assertion.
        rid1 = _new_request_id()
        await _seed_request(tid, rid1)
        bad_recipient = _sign(
            _assertion_xml(request_id=rid1, recipient="https://evil.example.com/acs"),
            idp.priv_pem,
            idp.cert_pem,
        )
        with pytest.raises((SamlConditionsInvalid, SamlSignatureInvalid)):
            await complete_login(_response_b64(inner=bad_recipient, request_id=rid1), rid1)

        # (b) wrong Destination on the <Response>.
        rid2 = _new_request_id()
        await _seed_request(tid, rid2)
        signed = _sign(_assertion_xml(request_id=rid2), idp.priv_pem, idp.cert_pem)
        bad_dest = _response_b64(
            inner=signed, request_id=rid2, destination="https://evil.example.com/acs"
        )
        with pytest.raises((SamlConditionsInvalid, SamlSignatureInvalid)):
            await complete_login(bad_dest, rid2)
    finally:
        await _cleanup(tid)


# --------------------------------------------------------------------------- #
# Vector 2 — tenant binding (wrong audience / issuer; owner-not-assertion)
# --------------------------------------------------------------------------- #
async def test_saml_tenant_binding(idp):
    """Wrong Audience and wrong Issuer each -> rejected. The returned tenant on a
    valid response is the idp_config OWNER (R1), never an assertion value."""
    tid = await _seed_tenant_and_config(idp.cert_pem)
    await _seed_group_mapping(tid, "platform-admins", "tenant_admin")
    try:
        # (a) wrong Audience.
        rid1 = _new_request_id()
        await _seed_request(tid, rid1)
        bad_aud = _sign(
            _assertion_xml(request_id=rid1, audience="https://attacker.example.com/sp"),
            idp.priv_pem,
            idp.cert_pem,
        )
        with pytest.raises((SamlConditionsInvalid, SamlSignatureInvalid)):
            await complete_login(_response_b64(inner=bad_aud, request_id=rid1), rid1)

        # (b) wrong Issuer.
        rid2 = _new_request_id()
        await _seed_request(tid, rid2)
        bad_iss = _sign(
            _assertion_xml(request_id=rid2, issuer="https://evil-idp.example.com/meta"),
            idp.priv_pem,
            idp.cert_pem,
        )
        b64_iss = _response_b64(
            inner=bad_iss, request_id=rid2, issuer="https://evil-idp.example.com/meta"
        )
        with pytest.raises((SamlConditionsInvalid, SamlSignatureInvalid)):
            await complete_login(b64_iss, rid2)

        # (c) positive: a valid response binds to the config OWNER tenant.
        rid3 = _new_request_id()
        await _seed_request(tid, rid3)
        good = _sign(_assertion_xml(request_id=rid3), idp.priv_pem, idp.cert_pem)
        identity = await complete_login(_response_b64(inner=good, request_id=rid3), rid3)
        assert identity.tenant_id == tid  # owner, never an assertion-supplied value
    finally:
        await _cleanup(tid)
