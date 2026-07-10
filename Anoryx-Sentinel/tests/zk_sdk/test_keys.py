"""Unit tests for F-032 key derivation."""

from __future__ import annotations

import pytest

from zk_sdk.exceptions import InvalidKeyError
from zk_sdk.keys import (
    derive_keys,
    derive_master_key_from_passphrase,
    generate_master_key,
)


def test_generate_master_key_is_32_bytes():
    assert len(generate_master_key()) == 32


def test_generate_master_key_is_random():
    assert generate_master_key() != generate_master_key()


def test_derive_keys_distinct_data_and_index():
    mk = generate_master_key()
    dk = derive_keys(mk)
    assert len(dk.data_key) == 32
    assert len(dk.index_key) == 32
    # domain separation: the two sub-keys must differ
    assert dk.data_key != dk.index_key


def test_derive_keys_deterministic():
    mk = generate_master_key()
    assert derive_keys(mk).data_key == derive_keys(mk).data_key


def test_derive_keys_rejects_wrong_length():
    with pytest.raises(InvalidKeyError):
        derive_keys(b"tooshort")


def test_passphrase_derivation_deterministic_with_salt():
    salt = b"0123456789abcdef"
    k1 = derive_master_key_from_passphrase("correct horse", salt=salt)
    k2 = derive_master_key_from_passphrase("correct horse", salt=salt)
    assert k1 == k2 and len(k1) == 32


def test_passphrase_different_salt_different_key():
    k1 = derive_master_key_from_passphrase("pw", salt=b"0123456789abcdef")
    k2 = derive_master_key_from_passphrase("pw", salt=b"fedcba9876543210")
    assert k1 != k2


def test_passphrase_rejects_short_salt():
    with pytest.raises(InvalidKeyError):
        derive_master_key_from_passphrase("pw", salt=b"short")


def test_keys_repr_redacts():
    dk = derive_keys(generate_master_key())
    assert "redacted" in repr(dk)
