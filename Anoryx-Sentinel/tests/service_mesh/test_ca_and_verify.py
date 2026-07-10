"""Mesh CA issuance + peer verification (F-034, ADR-0040).

Covers the authentication path: a mesh-issued leaf verifies; a leaf from a
DIFFERENT CA, a tampered leaf, an expired leaf, and a wrong-trust-domain leaf all
fail closed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from service_mesh.ca import MeshCa
from service_mesh.exceptions import CaError, PeerVerificationError
from service_mesh.identity import ComponentIdentity
from service_mesh.verify import verify_peer

TRUST_DOMAIN = "sentinel.mesh"


@pytest.fixture
def ca() -> MeshCa:
    return MeshCa.generate(TRUST_DOMAIN)


def test_issue_leaf_carries_identity_san(ca: MeshCa):
    ident = ComponentIdentity(trust_domain=TRUST_DOMAIN, component="gateway")
    cred = ca.issue(ident, ttl_hours=24)
    leaf = x509.load_pem_x509_certificate(cred.cert_pem)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [ident.uri]
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_verify_peer_accepts_mesh_leaf(ca: MeshCa):
    ident = ComponentIdentity(trust_domain=TRUST_DOMAIN, component="orchestration-emitter")
    cred = ca.issue(ident)
    peer = verify_peer(cred.cert_pem, ca.cert_pem())
    assert peer.identity == ident


def test_verify_peer_rejects_foreign_ca(ca: MeshCa):
    other = MeshCa.generate(TRUST_DOMAIN)
    cred = other.issue(ComponentIdentity(trust_domain=TRUST_DOMAIN, component="gateway"))
    # Leaf minted by `other` must NOT verify against `ca`'s trust bundle.
    with pytest.raises(PeerVerificationError):
        verify_peer(cred.cert_pem, ca.cert_pem())


def test_verify_peer_rejects_tampered_leaf(ca: MeshCa):
    cred = ca.issue(ComponentIdentity(trust_domain=TRUST_DOMAIN, component="gateway"))
    # Flip a byte in the DER-inside-PEM by corrupting the base64 body.
    lines = cred.cert_pem.split(b"\n")
    body_idx = 1
    corrupted = bytearray(lines[body_idx])
    corrupted[0] = corrupted[0] ^ 0x01 if corrupted[0] != 0x41 else 0x42
    lines[body_idx] = bytes(corrupted)
    tampered = b"\n".join(lines)
    with pytest.raises(PeerVerificationError):
        verify_peer(tampered, ca.cert_pem())


def test_verify_peer_rejects_expired_leaf(ca: MeshCa):
    cred = ca.issue(ComponentIdentity(trust_domain=TRUST_DOMAIN, component="gateway"), ttl_hours=1)
    # Evaluate "now" as two hours in the future -> past not_valid_after.
    future = datetime.now(timezone.utc) + timedelta(hours=2)
    with pytest.raises(PeerVerificationError):
        verify_peer(cred.cert_pem, ca.cert_pem(), now=future)


def test_ca_load_roundtrip_and_mismatch_rejected(ca: MeshCa):
    reloaded = MeshCa.load(ca.key_pem(), ca.cert_pem())
    assert reloaded.trust_domain == TRUST_DOMAIN
    # Mismatched key/cert pair fails closed.
    other = MeshCa.generate(TRUST_DOMAIN)
    with pytest.raises(CaError):
        MeshCa.load(other.key_pem(), ca.cert_pem())


def test_issue_rejects_wrong_trust_domain(ca: MeshCa):
    foreign = ComponentIdentity(trust_domain="other.mesh", component="gateway")
    with pytest.raises(CaError):
        ca.issue(foreign)


def test_verify_rejects_leaf_without_uri_san(ca: MeshCa):
    """A cert signed by the mesh CA but lacking a URI SAN must fail closed."""
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    # Hand-build a leaf signed by the CA's key but with a DNS SAN, no URI SAN.
    ca_key = serialization.load_pem_private_key(ca.key_pem(), password=None)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue")]))
        .issuer_name(ca.cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("rogue.local")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(PeerVerificationError):
        verify_peer(leaf_pem, ca.cert_pem())
