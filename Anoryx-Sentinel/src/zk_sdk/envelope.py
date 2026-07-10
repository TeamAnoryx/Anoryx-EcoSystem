"""AES-256-GCM record envelope for the F-032 ZK storage SDK (ADR-0038).

Encrypts a record's plaintext with the client-held DATA key into a
server-storable `EncryptedRecord`. Uses `cryptography`'s AES-256-GCM (no
hand-rolled crypto, R3), a fresh 12-byte random nonce per record (GCM nonce
reuse under one key is catastrophic, so never reused), and optional AAD to bind
the ciphertext to a server-visible record id (tamper on the id -> decrypt
fails).

The EncryptedRecord is the ONLY thing that goes to the server: base64
ciphertext, base64 nonce, and blind-index tags. It contains NO plaintext and NO
key material (proven by tests/zk_sdk/test_no_plaintext_leak.py).
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zk_sdk.exceptions import DecryptionError, InvalidKeyError

_NONCE_BYTES = 12
_DATA_KEY_BYTES = 32


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


@dataclass(frozen=True)
class EncryptedRecord:
    """The server-storable ciphertext form of a record.

    scheme pins the crypto version so a future change is detectable. index_tags
    maps field_name -> blind-index hex tag (equality-searchable, see
    blind_index.py's leakage note). NOTHING here is plaintext or key material.
    """

    scheme: str
    nonce_b64: str
    ciphertext_b64: str
    index_tags: dict[str, str] = field(default_factory=dict)

    def to_server_dict(self) -> dict:
        """Return the exact JSON-serialisable dict a server would store."""
        return {
            "scheme": self.scheme,
            "nonce_b64": self.nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
            "index_tags": dict(self.index_tags),
        }

    @classmethod
    def from_server_dict(cls, d: dict) -> "EncryptedRecord":
        return cls(
            scheme=d["scheme"],
            nonce_b64=d["nonce_b64"],
            ciphertext_b64=d["ciphertext_b64"],
            index_tags=dict(d.get("index_tags", {})),
        )


_SCHEME = "anoryx-zk/aes-256-gcm/v1"


def encrypt_record(
    data_key: bytes,
    plaintext: bytes,
    *,
    aad: bytes | None = None,
    index_tags: dict[str, str] | None = None,
) -> EncryptedRecord:
    """Encrypt plaintext into an EncryptedRecord with a fresh random nonce.

    aad (associated data, e.g. a record id) is authenticated but NOT encrypted —
    tampering with it makes decryption fail. index_tags are attached verbatim
    (the caller computes them via blind_index).
    """
    if len(data_key) != _DATA_KEY_BYTES:
        raise InvalidKeyError(f"data key must be {_DATA_KEY_BYTES} bytes, got {len(data_key)}")
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(data_key).encrypt(nonce, plaintext, aad)
    return EncryptedRecord(
        scheme=_SCHEME,
        nonce_b64=_b64e(nonce),
        ciphertext_b64=_b64e(ct),
        index_tags=dict(index_tags or {}),
    )


def decrypt_record(data_key: bytes, record: EncryptedRecord, *, aad: bytes | None = None) -> bytes:
    """Decrypt an EncryptedRecord. Raises DecryptionError on wrong key / tamper.

    Fail-closed: a failed GCM tag check (wrong key, altered nonce/ciphertext, or
    altered aad) raises DecryptionError — never returns a guessed plaintext.
    """
    if len(data_key) != _DATA_KEY_BYTES:
        raise InvalidKeyError(f"data key must be {_DATA_KEY_BYTES} bytes, got {len(data_key)}")
    if record.scheme != _SCHEME:
        raise DecryptionError(f"unsupported scheme {record.scheme!r}")
    try:
        nonce = _b64d(record.nonce_b64)
        ct = _b64d(record.ciphertext_b64)
    except Exception as exc:
        raise DecryptionError("malformed base64 in record") from exc
    try:
        return AESGCM(data_key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed (wrong key or tampered ciphertext)") from exc
