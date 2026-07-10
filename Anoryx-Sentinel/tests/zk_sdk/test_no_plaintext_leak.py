"""The core F-032 ZK property: the server-side representation leaks no plaintext
and no key material. If these tests ever fail, the ZK claim is broken.
"""

from __future__ import annotations

import json

from zk_sdk.keys import derive_keys, generate_master_key
from zk_sdk.sdk import ZkClient

_SECRET_VALUES = ["patient@hospital.org", "diagnosis-J45", "supersecretnote", "1234567890"]


def test_server_dict_contains_no_plaintext():
    master = generate_master_key()
    c = ZkClient(master)
    payload = {
        "email": _SECRET_VALUES[0],
        "code": _SECRET_VALUES[1],
        "note": _SECRET_VALUES[2],
        "acct": _SECRET_VALUES[3],
    }
    rec = c.encrypt(payload, record_id="r1", index_fields=["email"])
    blob = json.dumps(rec.to_server_dict())
    # NONE of the plaintext values may appear anywhere in the server blob.
    for secret in _SECRET_VALUES:
        assert secret not in blob, f"plaintext {secret!r} leaked into server representation!"


def test_server_dict_contains_no_key_material():
    master = generate_master_key()
    keys = derive_keys(master)
    c = ZkClient(master)
    rec = c.encrypt({"email": "a@b.com"}, index_fields=["email"])
    blob = json.dumps(rec.to_server_dict()).encode()
    # neither the master key nor the derived sub-keys may appear in the blob
    assert master not in blob
    assert keys.data_key not in blob
    assert keys.index_key not in blob


def test_server_dict_only_expected_keys():
    c = ZkClient(generate_master_key())
    rec = c.encrypt({"email": "a@b.com"}, index_fields=["email"])
    assert set(rec.to_server_dict().keys()) == {
        "scheme",
        "nonce_b64",
        "ciphertext_b64",
        "index_tags",
    }


def test_blind_index_tag_does_not_reveal_value():
    c = ZkClient(generate_master_key())
    rec = c.encrypt({"email": "patient@hospital.org"}, index_fields=["email"])
    # the tag is an HMAC digest, not the value
    assert "patient@hospital.org" not in rec.index_tags["email"]
    assert "hospital" not in rec.index_tags["email"]
