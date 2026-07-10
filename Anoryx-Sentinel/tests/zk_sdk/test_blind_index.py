"""Unit tests for F-032 blind-index tags (equality search + its leakage)."""

from __future__ import annotations

from zk_sdk.blind_index import blind_index_tag
from zk_sdk.keys import derive_keys, generate_master_key


def _ik():
    return derive_keys(generate_master_key()).index_key


def test_same_value_same_tag_enables_equality_search():
    ik = _ik()
    # deterministic: identical (field, value) -> identical tag (this is what lets
    # the server match equality — and is exactly the equality-leakage tradeoff).
    assert blind_index_tag(ik, "email", "a@b.com") == blind_index_tag(ik, "email", "a@b.com")


def test_different_value_different_tag():
    ik = _ik()
    assert blind_index_tag(ik, "email", "a@b.com") != blind_index_tag(ik, "email", "c@d.com")


def test_field_name_separates_tags():
    ik = _ik()
    # same value under different fields -> different tags (no cross-field correlation)
    assert blind_index_tag(ik, "email", "x") != blind_index_tag(ik, "username", "x")


def test_different_index_key_different_tag():
    v = ("email", "a@b.com")
    assert blind_index_tag(_ik(), *v) != blind_index_tag(_ik(), *v)


def test_tag_is_hex_128_bits():
    tag = blind_index_tag(_ik(), "f", "v")
    assert len(tag) == 32  # 16 bytes hex
    int(tag, 16)  # valid hex
