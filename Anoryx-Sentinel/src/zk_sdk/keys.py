"""Client-held key material for the F-032 ZK storage SDK (ADR-0038).

The MASTER key is 32 bytes held ONLY by the client. From it we derive, via
HKDF-SHA256 with distinct `info` labels (domain separation), two sub-keys:
  - the DATA key  — used for AES-256-GCM record encryption (envelope.py);
  - the INDEX key — used for HMAC blind-index tags (blind_index.py).

Deriving distinct sub-keys means a blind-index tag can never be used to attack
the data ciphertext and vice-versa. No crypto is hand-rolled (R3) — HKDF and
scrypt come from `cryptography`.

KEYS NEVER LEAVE THE CLIENT. This module has NO serialization of the raw key to
any server-bound form, NO logging, and the CLI writes the master key only to a
local file the operator controls. That is the core ZK property, enforced by
construction + tested (tests/zk_sdk/test_no_plaintext_leak.py).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from zk_sdk.exceptions import InvalidKeyError

_MASTER_KEY_BYTES = 32
_SUBKEY_BYTES = 32

_INFO_DATA = b"anoryx-zk-sdk/v1/data-key"
_INFO_INDEX = b"anoryx-zk-sdk/v1/index-key"

# scrypt parameters for passphrase-derived master keys (OWASP-adjacent; interactive).
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


def generate_master_key() -> bytes:
    """Return a fresh random 32-byte master key (client-held)."""
    return os.urandom(_MASTER_KEY_BYTES)


def derive_master_key_from_passphrase(passphrase: str, *, salt: bytes) -> bytes:
    """Derive a 32-byte master key from a passphrase via scrypt.

    `salt` must be stored by the CLIENT (it is not secret, but is needed to
    re-derive the same key). A 16-byte random salt is recommended.
    """
    if not passphrase:
        raise InvalidKeyError("passphrase must not be empty")
    if len(salt) < 16:
        raise InvalidKeyError("salt must be at least 16 bytes")
    kdf = Scrypt(salt=salt, length=_MASTER_KEY_BYTES, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _hkdf(master_key: bytes, info: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=_SUBKEY_BYTES, salt=None, info=info)
    return hkdf.derive(master_key)


@dataclass(frozen=True)
class DerivedKeys:
    """The two sub-keys derived from a master key. Client-held; never serialized."""

    data_key: bytes
    index_key: bytes

    def __repr__(self) -> str:  # pragma: no cover — defense in depth (no key in repr)
        return "DerivedKeys(data_key=<redacted>, index_key=<redacted>)"


def derive_keys(master_key: bytes) -> DerivedKeys:
    """Derive the data + index sub-keys from a 32-byte master key."""
    if len(master_key) != _MASTER_KEY_BYTES:
        raise InvalidKeyError(
            f"master key must be {_MASTER_KEY_BYTES} bytes, got {len(master_key)}"
        )
    return DerivedKeys(
        data_key=_hkdf(master_key, _INFO_DATA),
        index_key=_hkdf(master_key, _INFO_INDEX),
    )
