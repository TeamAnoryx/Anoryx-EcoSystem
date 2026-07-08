"""Pure unit tests (no DB) for ``persistence/hash_chain.py`` (R-009).

Mirrors ``Anoryx-Sentinel/tests/persistence/test_hash_chain_unit.py``'s coverage shape for the
same algorithm, adapted for Rendly's two record kinds (messages, huddles) and per-scope chains.
"""

from __future__ import annotations

from rendly.persistence import hash_chain


def test_genesis_hashes_are_reproducible_and_domain_separated() -> None:
    assert hash_chain.MESSAGE_GENESIS_HASH != hash_chain.HUDDLE_GENESIS_HASH
    assert len(hash_chain.MESSAGE_GENESIS_HASH) == 64
    assert len(hash_chain.HUDDLE_GENESIS_HASH) == 64
    assert all(c in "0123456789abcdef" for c in hash_chain.MESSAGE_GENESIS_HASH)


def test_canonical_json_is_deterministic_sorted_and_compact() -> None:
    data = {"b": 2, "a": 1, "prev_record_hash": "x" * 64}
    fields = ("a", "b", "prev_record_hash")
    out1 = hash_chain.canonical_json(data, fields)
    out2 = hash_chain.canonical_json(data, fields)
    assert out1 == out2
    assert b" " not in out1  # compact separators, no whitespace
    assert out1.index(b'"a"') < out1.index(b'"b"')  # sort_keys


def test_canonical_json_folds_missing_field_to_null_not_dropped() -> None:
    fields = ("a", "b", "prev_record_hash")
    with_b = hash_chain.canonical_json({"a": 1, "b": 2, "prev_record_hash": "x" * 64}, fields)
    without_b = hash_chain.canonical_json({"a": 1, "prev_record_hash": "x" * 64}, fields)
    assert with_b != without_b  # a missing field is NOT silently equivalent to an omitted one


def test_canonical_json_ignores_extra_keys_outside_fields() -> None:
    fields = ("a", "prev_record_hash")
    base = hash_chain.canonical_json({"a": 1, "prev_record_hash": "x" * 64}, fields)
    with_extra = hash_chain.canonical_json(
        {"a": 1, "prev_record_hash": "x" * 64, "unrelated": "ignored"}, fields
    )
    assert base == with_extra


def test_compute_row_hash_is_64_hex_and_deterministic() -> None:
    data = {"tenant_id": "t1", "prev_record_hash": hash_chain.MESSAGE_GENESIS_HASH}
    fields = ("tenant_id", "prev_record_hash")
    h1 = hash_chain.compute_row_hash(data, fields)
    h2 = hash_chain.compute_row_hash(data, fields)
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_compute_row_hash_changes_on_any_field_change() -> None:
    fields = ("tenant_id", "content", "prev_record_hash")
    base = {"tenant_id": "t1", "content": "hello", "prev_record_hash": "a" * 64}
    h_base = hash_chain.compute_row_hash(base, fields)

    changed_content = dict(base, content="goodbye")
    assert hash_chain.compute_row_hash(changed_content, fields) != h_base

    changed_prev = dict(base, prev_record_hash="b" * 64)
    assert hash_chain.compute_row_hash(changed_prev, fields) != h_base


def test_compute_row_hash_requires_nonempty_prev_record_hash() -> None:
    import pytest

    fields = ("tenant_id", "prev_record_hash")
    with pytest.raises(ValueError):
        hash_chain.compute_row_hash({"tenant_id": "t1", "prev_record_hash": None}, fields)
    with pytest.raises(ValueError):
        hash_chain.compute_row_hash({"tenant_id": "t1"}, fields)


def test_verify_row_hash_true_on_match_false_on_tamper() -> None:
    fields = ("tenant_id", "content", "prev_record_hash")
    data = {"tenant_id": "t1", "content": "hello", "prev_record_hash": "a" * 64}
    digest = hash_chain.compute_row_hash(data, fields)

    assert hash_chain.verify_row_hash(data, fields, digest) is True
    tampered = dict(data, content="tampered")
    assert hash_chain.verify_row_hash(tampered, fields, digest) is False


def test_three_row_chain_links_correctly() -> None:
    """A minimal simulated chain: row N's prev_record_hash must equal row N-1's digest."""
    fields = ("tenant_id", "seq", "prev_record_hash")

    row0 = {"tenant_id": "t1", "seq": 0, "prev_record_hash": hash_chain.MESSAGE_GENESIS_HASH}
    h0 = hash_chain.compute_row_hash(row0, fields)

    row1 = {"tenant_id": "t1", "seq": 1, "prev_record_hash": h0}
    h1 = hash_chain.compute_row_hash(row1, fields)

    row2 = {"tenant_id": "t1", "seq": 2, "prev_record_hash": h1}
    h2 = hash_chain.compute_row_hash(row2, fields)

    assert len({h0, h1, h2}) == 3  # all distinct
    assert hash_chain.verify_row_hash(row0, fields, h0)
    assert hash_chain.verify_row_hash(row1, fields, h1)
    assert hash_chain.verify_row_hash(row2, fields, h2)
    # Tampering row1's content (its seq) breaks ONLY row1's own digest verification, but a real
    # chain walker would also notice row2.prev_record_hash no longer matches a recomputed row1.
    tampered_row1 = dict(row1, seq=99)
    assert not hash_chain.verify_row_hash(tampered_row1, fields, h1)
