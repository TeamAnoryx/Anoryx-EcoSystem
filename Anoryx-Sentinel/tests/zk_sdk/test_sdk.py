"""Unit tests for the F-032 ZkClient high-level API."""

from __future__ import annotations

import pytest

from zk_sdk.exceptions import DecryptionError
from zk_sdk.keys import generate_master_key
from zk_sdk.sdk import ZkClient


def _client():
    return ZkClient(generate_master_key())


def test_encrypt_decrypt_round_trip():
    c = _client()
    payload = {"email": "a@b.com", "note": "hello", "n": 42}
    rec = c.encrypt(payload, record_id="r1")
    assert c.decrypt(rec, record_id="r1") == payload


def test_index_field_tag_matches_query_tag():
    c = _client()
    payload = {"email": "a@b.com", "note": "x"}
    rec = c.encrypt(payload, index_fields=["email"])
    # the server would match this stored tag against a client query tag
    assert rec.index_tags["email"] == c.query_tag("email", "a@b.com")
    # a different value's query tag does NOT match
    assert rec.index_tags["email"] != c.query_tag("email", "z@z.com")


def test_two_records_same_value_share_tag_but_not_ciphertext():
    c = _client()
    r1 = c.encrypt({"email": "same@x.com", "note": "one"}, index_fields=["email"])
    r2 = c.encrypt({"email": "same@x.com", "note": "two"}, index_fields=["email"])
    # equality leakage (by design): same email -> same tag ...
    assert r1.index_tags["email"] == r2.index_tags["email"]
    # ... but the payloads stay confidential (different nonce/ciphertext)
    assert r1.ciphertext_b64 != r2.ciphertext_b64


def test_record_id_binding_enforced():
    c = _client()
    rec = c.encrypt({"a": 1}, record_id="r1")
    with pytest.raises(DecryptionError):
        c.decrypt(rec, record_id="r2")


def test_non_indexed_field_absent_from_tags():
    c = _client()
    rec = c.encrypt({"email": "a@b.com", "secret": "s"}, index_fields=["email"])
    assert "secret" not in rec.index_tags


def test_unindexable_value_type_rejected():
    c = _client()
    with pytest.raises(TypeError):
        c.encrypt({"obj": {"nested": 1}}, index_fields=["obj"])
