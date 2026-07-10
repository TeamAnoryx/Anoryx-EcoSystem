"""Peer verification + app-layer authorization (F-034, ADR-0040).

Two distinct checks, both fail-closed (CLAUDE.md #5):

1. `verify_peer(leaf_pem, ca_pem)` — AUTHENTICATION. Confirms a peer's leaf
   certificate:
     - is signed by the mesh CA (ECDSA signature over the leaf's TBS bytes),
     - was issued by the CA (issuer == CA subject),
     - is inside its validity window (with small skew tolerance),
     - carries exactly one mesh URI-SAN identity in the CA's trust domain.
   Returns the verified `ComponentIdentity`. Any failure raises.

   This is deliberately a small, explicit verifier rather than a full path
   builder: the mesh CA signs leaves directly (path-length 0), so the chain is
   always leaf -> CA. TLS-layer verification still runs via `ssl_context`
   (CERT_REQUIRED); this function is the app-layer identity extraction + the
   authoritative re-check callers use to make authorization decisions.

2. `MeshAuthorizationPolicy` — AUTHORIZATION. mTLS proves WHO a peer is; it does
   not say whether that peer may call THIS endpoint. The policy is an explicit
   allow-list of `caller-component -> {callee-components}`. Default deny.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from service_mesh.exceptions import (
    InvalidIdentityError,
    MeshAuthorizationError,
    PeerVerificationError,
)
from service_mesh.identity import ComponentIdentity

# Tolerance for clock skew between the verifier and the issuer/peer.
_SKEW = timedelta(minutes=5)


@dataclass(frozen=True)
class VerifiedPeer:
    """The result of a successful peer verification."""

    identity: ComponentIdentity
    not_valid_after: datetime


def _load(leaf_pem: bytes, ca_pem: bytes) -> tuple[x509.Certificate, x509.Certificate]:
    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem)
        ca = x509.load_pem_x509_certificate(ca_pem)
    except (ValueError, TypeError) as exc:
        raise PeerVerificationError(f"could not parse certificate PEM: {exc}") from exc
    return leaf, ca


def _check_signed_by(leaf: x509.Certificate, ca: x509.Certificate) -> None:
    ca_pub = ca.public_key()
    try:
        if isinstance(ca_pub, ec.EllipticCurvePublicKey):
            ca_pub.verify(
                leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
            )
        elif isinstance(ca_pub, rsa.RSAPublicKey):
            ca_pub.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf.signature_hash_algorithm,
            )
        else:  # pragma: no cover - mesh CA is always EC in this codebase
            raise PeerVerificationError("unsupported mesh CA key type")
    except InvalidSignature as exc:
        raise PeerVerificationError("peer leaf is not signed by the mesh CA") from exc


def _extract_identity(leaf: x509.Certificate, trust_domain: str) -> ComponentIdentity:
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise PeerVerificationError("peer leaf has no SubjectAlternativeName") from exc
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise PeerVerificationError(
            f"peer leaf must carry exactly one URI SAN identity, found {len(uris)}"
        )
    try:
        identity = ComponentIdentity.parse(uris[0])
    except InvalidIdentityError as exc:
        raise PeerVerificationError(f"peer leaf identity is not a mesh identity: {exc}") from exc
    if identity.trust_domain != trust_domain:
        raise PeerVerificationError(
            f"peer identity trust domain {identity.trust_domain!r} is outside this mesh "
            f"({trust_domain!r})"
        )
    return identity


def _ca_trust_domain(ca: x509.Certificate) -> str:
    from cryptography.x509.oid import NameOID

    attrs = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise PeerVerificationError("mesh CA certificate has no CommonName")
    cn = attrs[0].value
    if "(" not in cn or not cn.rstrip().endswith(")"):
        raise PeerVerificationError("mesh CA CommonName is not in the expected form")
    return cn.rsplit("(", 1)[-1].rstrip(")")


def verify_peer(leaf_pem: bytes, ca_pem: bytes, *, now: datetime | None = None) -> VerifiedPeer:
    """Verify a peer leaf against the mesh CA and return its identity. Fail-closed."""
    leaf, ca = _load(leaf_pem, ca_pem)
    now = now or datetime.now(timezone.utc)

    if leaf.issuer != ca.subject:
        raise PeerVerificationError("peer leaf issuer does not match the mesh CA subject")

    _check_signed_by(leaf, ca)

    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if now + _SKEW < not_before:
        raise PeerVerificationError(f"peer leaf is not yet valid (starts {not_before.isoformat()})")
    if now - _SKEW > not_after:
        raise PeerVerificationError(f"peer leaf has expired (ended {not_after.isoformat()})")

    trust_domain = _ca_trust_domain(ca)
    identity = _extract_identity(leaf, trust_domain)
    return VerifiedPeer(identity=identity, not_valid_after=not_after)


@dataclass(frozen=True)
class MeshAuthorizationPolicy:
    """Default-deny allow-list of caller-component -> allowed callee-components."""

    allow: dict[str, frozenset[str]]

    @classmethod
    def from_pairs(cls, pairs: dict[str, list[str] | set[str]]) -> MeshAuthorizationPolicy:
        return cls(allow={k: frozenset(v) for k, v in pairs.items()})

    def is_allowed(self, caller: ComponentIdentity, callee: ComponentIdentity) -> bool:
        """True iff `caller` is explicitly allowed to reach `callee` (same mesh)."""
        if caller.trust_domain != callee.trust_domain:
            return False
        return callee.component in self.allow.get(caller.component, frozenset())

    def enforce(self, caller: ComponentIdentity, callee: ComponentIdentity) -> None:
        """Raise MeshAuthorizationError unless the call is allowed."""
        if not self.is_allowed(caller, callee):
            raise MeshAuthorizationError(
                f"component {caller.component!r} is not authorized to call "
                f"{callee.component!r} in mesh {callee.trust_domain!r}"
            )
