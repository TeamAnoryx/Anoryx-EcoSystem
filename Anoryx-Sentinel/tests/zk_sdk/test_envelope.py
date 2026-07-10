"""Unit tests for F-032 AES-256-GCM record envelope."""

from __future__ import annotations

import base64

import pytest

from zk_sdk.envelope import decrypt_record, encrypt_record
from zk_sdk.exceptions import DecryptionError, InvalidKeyError
from zk_sdk.keys import derive_keys, generate_master_key


def _dk():
    return derive_keys(generate_master_key()).data_key


def test_round_trip():
    dk = _dk()
    pt = b"top secret payload"
    rec = encrypt_record(dk, pt)
    assert decrypt_record(dk, rec) == pt


def test_nonce_is_fresh_per_record():
    dk = _dk()
    r1 = encrypt_record(dk, b"same")
    r2 = encrypt_record(dk, b"same")
    # fresh random nonce -> different nonce and different ciphertext for same input
    assert r1.nonce_b64 != r2.nonce_b64
    assert r1.ciphertext_b64 != r2.ciphertext_b64


def test_wrong_key_fails_closed():
    rec = encrypt_record(_dk(), b"secret")
    with pytest.raises(DecryptionError):
        decrypt_record(_dk(), rec)  # different key


def test_tampered_ciphertext_fails():
    dk = _dk()
    rec = encrypt_record(dk, b"secret")
    tampered = base64.b64encode(base64.b64decode(rec.ciphertext_b64)[:-1] + b"\x00").decode()
    from dataclasses import replace

    with pytest.raises(DecryptionError):
        decrypt_record(dk, replace(rec, ciphertext_b64=tampered))


def test_aad_binding_detects_id_swap():
    dk = _dk()
    rec = encrypt_record(dk, b"secret", aad=b"record-1")
    # decrypting under a different record id must fail (id is authenticated)
    with pytest.raises(DecryptionError):
        decrypt_record(dk, rec, aad=b"record-2")
    # correct id works
    assert decrypt_record(dk, rec, aad=b"record-1") == b"secret"


def test_rejects_wrong_key_length():
    with pytest.raises(InvalidKeyError):
        encrypt_record(b"short", b"x")


def test_server_dict_round_trips():
    dk = _dk()
    rec = encrypt_record(dk, b"payload", index_tags={"email": "abc123"})
    from zk_sdk.envelope import EncryptedRecord

    restored = EncryptedRecord.from_server_dict(rec.to_server_dict())
    assert decrypt_record(dk, restored) == b"payload"
    assert restored.index_tags == {"email": "abc123"}
