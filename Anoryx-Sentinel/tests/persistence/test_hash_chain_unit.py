"""Unit tests for hash_chain module (F-003). No DB required.

Tests canonical JSON serialization, GENESIS_HASH computation,
and compute_row_hash determinism.

Item 4 regression: GENESIS_HASH must be exactly 64 hex chars AND equal
hashlib.sha256(b"anoryx-sentinel:events:genesis:v1").hexdigest().

Item 11: sort_keys=True is the canonical form.  Tests verify key order is
alphabetical (sort_keys=True), not CANONICAL_FIELDS insertion order.

Item 9: CANONICAL_FIELDS uses 'severity' (not 'pii_severity') and 'status'
(not 'compliance_status') to match contracts/events.schema.json exactly.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from persistence.hash_chain import (
    CANONICAL_FIELDS,
    GENESIS_HASH,
    canonical_json,
    compute_row_hash,
    verify_row_hash,
)


# ---------------------------------------------------------------------------
# GENESIS_HASH regression (item 4)
# ---------------------------------------------------------------------------


def test_genesis_hash_is_sha256_of_domain_string() -> None:
    """GENESIS_HASH must be SHA-256 of the documented domain-separation string."""
    expected = hashlib.sha256(b"anoryx-sentinel:events:genesis:v1").hexdigest()
    assert GENESIS_HASH == expected


def test_genesis_hash_is_exactly_64_hex_chars() -> None:
    """GENESIS_HASH must be exactly 64 lowercase hex characters."""
    assert len(GENESIS_HASH) == 64
    assert all(c in "0123456789abcdef" for c in GENESIS_HASH), (
        f"GENESIS_HASH contains non-hex chars: {GENESIS_HASH!r}"
    )


def test_genesis_hash_matches_computed_value() -> None:
    """GENESIS_HASH value must equal the dynamically computed hexdigest.

    This is the item 4 regression: the old model file had a 63-char hardcoded
    wrong value.  The correct value is always computed at import time from the
    domain-separation string, never hardcoded.
    """
    computed = hashlib.sha256(b"anoryx-sentinel:events:genesis:v1").hexdigest()
    assert GENESIS_HASH == computed, (
        f"GENESIS_HASH mismatch: got {GENESIS_HASH!r}, expected {computed!r}"
    )


def test_genesis_hash_is_not_trivially_guessable() -> None:
    """GENESIS_HASH must not be all-zeros, all-ones, or empty."""
    assert GENESIS_HASH != "0" * 64
    assert GENESIS_HASH != "f" * 64
    assert GENESIS_HASH != ""


# ---------------------------------------------------------------------------
# CANONICAL_FIELDS contract conformance (item 9)
# ---------------------------------------------------------------------------


def test_canonical_fields_uses_severity_not_pii_severity() -> None:
    """CANONICAL_FIELDS must contain 'severity', not 'pii_severity'."""
    assert "severity" in CANONICAL_FIELDS
    assert "pii_severity" not in CANONICAL_FIELDS


def test_canonical_fields_uses_status_not_compliance_status() -> None:
    """CANONICAL_FIELDS must contain 'status', not 'compliance_status'."""
    assert "status" in CANONICAL_FIELDS
    assert "compliance_status" not in CANONICAL_FIELDS


# ---------------------------------------------------------------------------
# Canonical JSON (item 11 — sort_keys=True is authoritative)
# ---------------------------------------------------------------------------


def _minimal_row_data() -> dict:
    return {
        "event_id": "abc123",
        "event_type": "usage",
        "event_timestamp": "2026-06-15T00:00:00Z",
        "request_id": "req-001",
        "tenant_id": "t1",
        "team_id": "team1",
        "project_id": "proj1",
        "agent_id": "gateway-core",
        "prev_hash": GENESIS_HASH,
        # All variant fields absent (None in canonical output)
    }


def test_canonical_json_is_deterministic() -> None:
    """Same input always produces the same canonical JSON bytes."""
    data = _minimal_row_data()
    result1 = canonical_json(data)
    result2 = canonical_json(data)
    assert result1 == result2


def test_canonical_json_has_no_whitespace() -> None:
    """Canonical JSON must not contain spaces or newlines."""
    data = _minimal_row_data()
    result = canonical_json(data)
    assert b" " not in result
    assert b"\n" not in result


def test_canonical_json_keys_are_sorted_alphabetically() -> None:
    """Keys in canonical JSON are sorted alphabetically (sort_keys=True).

    Item 11: sort_keys=True is the authoritative canonical form.
    The serialization order is alphabetical, not CANONICAL_FIELDS insertion order.
    """
    data = _minimal_row_data()
    result = canonical_json(data)
    parsed = json.loads(result)
    keys = list(parsed.keys())
    assert keys == sorted(keys), (
        f"Keys are not alphabetically sorted. Got: {keys}"
    )


def test_canonical_json_includes_all_canonical_fields() -> None:
    """canonical_json output must include all CANONICAL_FIELDS keys."""
    data = _minimal_row_data()
    result = canonical_json(data)
    parsed = json.loads(result)
    for field in CANONICAL_FIELDS:
        assert field in parsed, f"Field {field!r} missing from canonical JSON"


def test_canonical_json_missing_fields_produce_none() -> None:
    """Missing fields produce None values (not omitted) to prevent omission attacks."""
    data = _minimal_row_data()
    result = canonical_json(data)
    parsed = json.loads(result)
    # Fields not in data should be None.
    assert parsed.get("model") is None
    assert parsed.get("tokens_in") is None
    # Contract-conformant field names.
    assert "severity" in parsed   # not "pii_severity"
    assert "status" in parsed     # not "compliance_status"
    assert parsed.get("severity") is None
    assert parsed.get("status") is None


def test_compute_row_hash_is_64_char_hex() -> None:
    """compute_row_hash must return a 64-character lowercase hex string."""
    data = _minimal_row_data()
    h = compute_row_hash(data)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_compute_row_hash_is_deterministic() -> None:
    """Same input always produces the same row hash."""
    data = _minimal_row_data()
    h1 = compute_row_hash(data)
    h2 = compute_row_hash(data)
    assert h1 == h2


def test_compute_row_hash_changes_on_field_change() -> None:
    """Changing any field must produce a different hash."""
    data = _minimal_row_data()
    h_original = compute_row_hash(data)

    data_modified = dict(data)
    data_modified["event_timestamp"] = "2099-01-01T00:00:00Z"
    h_modified = compute_row_hash(data_modified)
    assert h_original != h_modified


def test_compute_row_hash_changes_on_prev_hash_change() -> None:
    """Changing prev_hash must produce a different row hash (prevents reordering)."""
    data = _minimal_row_data()
    h1 = compute_row_hash(data)

    data2 = dict(data)
    data2["prev_hash"] = "a" * 64
    h2 = compute_row_hash(data2)
    assert h1 != h2


def test_compute_row_hash_requires_prev_hash() -> None:
    """compute_row_hash raises ValueError if prev_hash is absent."""
    data = _minimal_row_data()
    del data["prev_hash"]
    with pytest.raises(ValueError, match="prev_hash"):
        compute_row_hash(data)


def test_compute_row_hash_requires_event_timestamp() -> None:
    """compute_row_hash raises ValueError if event_timestamp is absent."""
    data = _minimal_row_data()
    del data["event_timestamp"]
    with pytest.raises(ValueError, match="event_timestamp"):
        compute_row_hash(data)


def test_verify_row_hash_returns_true_for_correct_hash() -> None:
    """verify_row_hash returns True when the stored hash matches the recomputed one."""
    data = _minimal_row_data()
    h = compute_row_hash(data)
    assert verify_row_hash(data, h) is True


def test_verify_row_hash_returns_false_for_tampered_data() -> None:
    """verify_row_hash returns False when data has been tampered."""
    data = _minimal_row_data()
    h = compute_row_hash(data)
    tampered = dict(data)
    tampered["event_type"] = "pii_blocked"
    assert verify_row_hash(tampered, h) is False


def test_chain_links_correctly() -> None:
    """Simulate a 3-row chain and verify each row links to the previous."""
    rows = []
    prev = GENESIS_HASH

    for i in range(3):
        data = {
            "event_id": f"evt-{i}",
            "event_type": "usage",
            "event_timestamp": f"2026-06-15T0{i}:00:00Z",
            "request_id": f"req-{i}",
            "tenant_id": "t1",
            "team_id": "team1",
            "project_id": "proj1",
            "agent_id": "gateway-core",
            "prev_hash": prev,
        }
        row_hash = compute_row_hash(data)
        rows.append({"data": data, "row_hash": row_hash})
        prev = row_hash

    # Verify chain: each row's prev_hash links to previous row_hash.
    assert rows[0]["data"]["prev_hash"] == GENESIS_HASH
    assert rows[1]["data"]["prev_hash"] == rows[0]["row_hash"]
    assert rows[2]["data"]["prev_hash"] == rows[1]["row_hash"]


# ---------------------------------------------------------------------------
# database.py session decorator test (item 5)
# ---------------------------------------------------------------------------


def test_get_async_session_is_asynccontextmanager() -> None:
    """get_async_session must be decorated with @asynccontextmanager.

    This is a structural check only — no DB connection required.
    Without @asynccontextmanager, 'async with get_async_session()' would raise
    AttributeError at runtime because the bare async generator has no __aenter__.
    """
    from contextlib import _AsyncGeneratorContextManager

    from persistence.database import get_async_session

    # The function object itself should be wrapped (it has __wrapped__ or is callable).
    # Calling it without arguments should produce an _AsyncGeneratorContextManager.
    # We use DATABASE_URL guard to avoid needing a real DB in this unit test.
    import os

    original = os.environ.get("DATABASE_URL")
    try:
        os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost:5432/test"
        ctx = get_async_session()
        assert hasattr(ctx, "__aenter__"), (
            "get_async_session() must return an async context manager "
            "(decorated with @asynccontextmanager)"
        )
        assert hasattr(ctx, "__aexit__"), (
            "get_async_session() must return an async context manager "
            "(decorated with @asynccontextmanager)"
        )
    finally:
        if original is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = original


def test_database_module_exposes_only_get_async_session() -> None:
    """database.py must expose get_async_session and NOT the F-003b session helpers.

    get_tenant_session and get_privileged_session are deferred to F-003b.
    Importing them from database must raise ImportError in F-003.
    """
    import importlib

    import persistence.database as db_mod

    assert hasattr(db_mod, "get_async_session"), (
        "get_async_session must exist in database.py"
    )
    assert not hasattr(db_mod, "get_tenant_session"), (
        "get_tenant_session must NOT be in database.py for F-003; it is deferred to F-003b"
    )
    assert not hasattr(db_mod, "get_privileged_session"), (
        "get_privileged_session must NOT be in database.py for F-003; it is deferred to F-003b"
    )
