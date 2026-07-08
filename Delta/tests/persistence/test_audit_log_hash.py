"""D-009 pure hash-chain algorithm tests — no DB, mirrors Sentinel's hash_chain.py suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from delta.persistence.audit_log import GENESIS_HASH, compute_row_hash

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


def _base(**over: object) -> dict:
    fields: dict = {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "entity_type": "allocation",
        "entity_id": "22222222-2222-2222-2222-222222222222",
        "action": "requested",
        "actor": "operator-1",
        "created_at": _NOW.isoformat(),
        "prev_hash": GENESIS_HASH,
    }
    fields.update(over)
    return fields


def test_genesis_hash_is_a_stable_known_value() -> None:
    # Locks the algorithm to a hardcoded literal (not recomputed from the same source
    # string the module uses — that would only prove internal self-consistency, not
    # that the constant is what every already-backfilled chain's first link expects).
    # Changing GENESIS_HASH is a breaking change to every existing chain; this test
    # must be updated deliberately, never accidentally.
    assert GENESIS_HASH == "031004c45b05a0548f85110753aee06bf2f836b8f5febd1ff7c477914fd1b3c2"
    assert len(GENESIS_HASH) == 64


def test_compute_row_hash_requires_prev_hash() -> None:
    data = _base()
    del data["prev_hash"]
    with pytest.raises(ValueError, match="prev_hash"):
        compute_row_hash(data)


def test_compute_row_hash_requires_created_at() -> None:
    data = _base()
    del data["created_at"]
    with pytest.raises(ValueError, match="created_at"):
        compute_row_hash(data)


def test_compute_row_hash_is_deterministic() -> None:
    data = _base()
    assert compute_row_hash(data) == compute_row_hash(dict(data))


def test_compute_row_hash_changes_if_action_changes() -> None:
    assert compute_row_hash(_base(action="requested")) != compute_row_hash(_base(action="approved"))


def test_compute_row_hash_changes_if_prev_hash_changes() -> None:
    other_prev = "a" * 64
    assert compute_row_hash(_base()) != compute_row_hash(_base(prev_hash=other_prev))


def test_note_absent_and_note_none_hash_identically() -> None:
    # Opt-in-when-present (banked rule #8): a row with no 'note' key at all (an older
    # schema that never had the column) and a row with note=None must hash the SAME —
    # this is what lets a future optional column be added with zero backfill.
    without_key = _base()
    with_none = _base(note=None)
    assert compute_row_hash(without_key) == compute_row_hash(with_none)


def test_note_present_changes_the_hash() -> None:
    without_note = compute_row_hash(_base())
    with_note = compute_row_hash(_base(note="approved after review"))
    assert without_note != with_note


def test_note_value_is_bound_into_the_hash() -> None:
    a = compute_row_hash(_base(note="reason A"))
    b = compute_row_hash(_base(note="reason B"))
    assert a != b
