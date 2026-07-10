"""Internal mesh certificate authority (F-034, ADR-0040).

Generates the mesh CA and issues SHORT-LIVED component leaf certificates. Design
choices, all in service of a small, auditable mTLS mesh:

- **EC P-256 keys** — small, fast, universally supported for TLS.
- **Short leaf TTL** (default 24h) — mesh certs are meant to rotate constantly;
  a leaked leaf is only useful for its short remaining validity. See `rotation`.
- **URI SAN identity** — the leaf carries `ComponentIdentity.uri` as its only
  identity (no reliance on CN), so verification is unambiguous.
- **EKU serverAuth + clientAuth** — a component is BOTH a server (accepts mTLS)
  and a client (initiates mTLS to peers), so every leaf carries both.
- **Path-length 0 CA** — the mesh CA signs leaves only, never sub-CAs.

Key handling is fail-closed: a malformed/oversize key file, or a private key that
does not match its certificate, raises `CaError`. In production the CA private
key lives in Vault/KMS and is injected at runtime (CLAUDE.md #4); on-disk PEM is
for local/dev and the CLI's operator workflow only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from service_mesh.exceptions import CaError
from service_mesh.identity import ComponentIdentity

# A mesh CA is long-lived relative to leaves, but not eternal: default 5 years.
_DEFAULT_CA_VALIDITY_DAYS = 365 * 5
# Leaves are short-lived and rotated aggressively (see rotation.py).
DEFAULT_LEAF_TTL_HOURS = 24
# Small clock-skew backdating so a freshly minted leaf validates on a peer whose
# clock is a little behind.
_BACKDATE = timedelta(minutes=5)


@dataclass(frozen=True)
class IssuedCredential:
    """A freshly issued leaf: its certificate + the matching private key (PEM)."""

    identity: ComponentIdentity
    cert_pem: bytes
    key_pem: bytes


class MeshCa:
    """The mesh CA: an EC private key + its self-signed CA certificate."""

    def __init__(self, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
        self._key = key
        self._cert = cert

    # ---- construction -------------------------------------------------------
    @classmethod
    def generate(
        cls, trust_domain: str, *, validity_days: int = _DEFAULT_CA_VALIDITY_DAYS
    ) -> MeshCa:
        """Generate a brand-new mesh CA for `trust_domain`."""
        # Validate the trust domain via ComponentIdentity's rules (reuse the regex).
        ComponentIdentity(trust_domain=trust_domain, component="ca")
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"Anoryx Sentinel Mesh CA ({trust_domain})")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _BACKDATE)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert)

    @classmethod
    def load(cls, key_pem: bytes, cert_pem: bytes) -> MeshCa:
        """Load an existing CA from PEM, fail-closed if the key/cert don't match."""
        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
            cert = x509.load_pem_x509_certificate(cert_pem)
        except (ValueError, TypeError) as exc:
            raise CaError(f"could not load mesh CA key/cert: {exc}") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CaError("mesh CA key must be an EC private key")
        # The private key must correspond to the certificate's public key.
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise CaError("mesh CA private key does not match its certificate")
        if not _is_ca(cert):
            raise CaError("mesh CA certificate is not a CA certificate")
        return cls(key, cert)

    # ---- issuance -----------------------------------------------------------
    def issue(
        self, identity: ComponentIdentity, *, ttl_hours: int = DEFAULT_LEAF_TTL_HOURS
    ) -> IssuedCredential:
        """Issue a short-lived leaf for `identity`. Fresh key per issuance."""
        if ttl_hours <= 0:
            raise CaError("leaf ttl_hours must be positive")
        if identity.trust_domain != self.trust_domain:
            raise CaError(
                f"identity trust domain {identity.trust_domain!r} does not match "
                f"CA trust domain {self.trust_domain!r}"
            )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity.component)]))
            .issuer_name(self._cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _BACKDATE)
            .not_valid_after(now + timedelta(hours=ttl_hours))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_agreement=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            # The mesh identity — a URI SAN, the ONLY identity verifiers trust.
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity.uri)]),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._cert.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return IssuedCredential(
            identity=identity,
            cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            key_pem=key_pem,
        )

    # ---- accessors ----------------------------------------------------------
    @property
    def trust_domain(self) -> str:
        cn = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        # CN is "Anoryx Sentinel Mesh CA (<trust-domain>)"
        return cn.rsplit("(", 1)[-1].rstrip(")")

    @property
    def cert(self) -> x509.Certificate:
        return self._cert

    def cert_pem(self) -> bytes:
        """The CA certificate PEM — the mesh trust bundle verifiers load."""
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def key_pem(self) -> bytes:
        """The CA private key PEM. Handle as a secret (Vault/KMS in prod)."""
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return bool(bc.ca)
