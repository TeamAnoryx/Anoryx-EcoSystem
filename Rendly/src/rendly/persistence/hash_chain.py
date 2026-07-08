"""Hash-chain primitives for immutable archiving (R-009).

Reuses the Anoryx-Sentinel F-003 audit pattern verbatim (SHA-256 over canonical JSON, a
prev-hash chain-of-custody link, a domain-separated genesis constant) — see
``Anoryx-Sentinel/src/persistence/hash_chain.py``. The one structural difference: Sentinel
runs ONE global chain across every tenant (a single ``events_audit_log`` table, ordered by a
table-wide ``sequence_number``); Rendly runs SCOPED chains — one per (tenant_id, channel_id)
for chat messages, one per tenant_id for huddle sessions — matching the wire contract's own
``ArchivalMeta.seq`` description ("Monotonic per-channel (messages) / per-tenant (huddles)
ordering sequence", ``contracts/messages.schema.json``). Each scope starts from its own
``prev_record_hash = None`` and chains from the record kind's GENESIS constant.

This module is PURE (no DB / SQLAlchemy import) so it is trivially unit-testable and so the
two callers (``persistence/chat_repo.py`` for messages, ``persistence/huddle_repo.py`` for
huddles) can share one hashing implementation without a persistence-layer import cycle.

CANONICAL FIELD LISTS (the omission-attack guard, mirrored from Sentinel): a field present in
a record kind's field list but absent from the input dict is folded in as ``null`` rather than
silently dropped, so a caller cannot shrink the hashed surface by forgetting to pass a field.
``prev_record_hash`` is always LAST in each list so a chain-linking bug surfaces as a hash
mismatch, not a silently-reordered digest (same rationale as Sentinel's ``CANONICAL_FIELDS``).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

__all__ = [
    "MESSAGE_GENESIS_HASH",
    "HUDDLE_GENESIS_HASH",
    "MESSAGE_CANONICAL_FIELDS",
    "HUDDLE_CANONICAL_FIELDS",
    "canonical_json",
    "compute_row_hash",
    "verify_row_hash",
]


def _genesis_hash(domain: str) -> str:
    """A reproducible, domain-separated genesis constant (computed, never hand-hardcoded)."""
    return hashlib.sha256(f"rendly:{domain}:genesis:v1".encode("utf-8")).hexdigest()


# The chain-start constant for a scope's FIRST record (no real predecessor exists yet).
MESSAGE_GENESIS_HASH = _genesis_hash("messages")
HUDDLE_GENESIS_HASH = _genesis_hash("huddles")

# The exact field set each record kind hashes over. Order here is documentation only — the
# actual digest input is sorted-key JSON (see canonical_json) — except that prev_record_hash
# is placed last to match Sentinel's convention.
MESSAGE_CANONICAL_FIELDS: tuple[str, ...] = (
    "tenant_id",
    "channel_id",
    "message_id",
    "sender_user_id",
    "content",
    "content_type",
    "seq",
    "created_at",
    "inspection_status",
    "detectors",
    "prev_record_hash",
)

HUDDLE_CANONICAL_FIELDS: tuple[str, ...] = (
    "tenant_id",
    "huddle_id",
    # R-011 (ADR-0011 Fork G): a SORTED, order-independent list of every participant id,
    # replacing the two named caller_id/callee_id scalar fields. Strict generalization — a
    # 2-element sorted list carries the exact same information the old scalars did. The
    # caller (persistence/huddle_repo.py) is responsible for sorting before this is called;
    # canonical_json's own sort_keys=True only orders dict KEYS, not list contents.
    # HONESTY BOUNDARY (verbatim, non-removable): a huddle row archived BEFORE this field-list
    # change was hashed under the OLD (caller_id, callee_id) scalar fields — a future
    # chain-verifier task must account for this field-list boundary at the migration that
    # introduced it (mirrors the message-chain coverage boundary from ADR-0009).
    "participant_ids",
    "state",
    "seq",
    "created_at",
    "ended_at",
    "prev_record_hash",
)


def canonical_json(data: Mapping[str, Any], fields: tuple[str, ...]) -> bytes:
    """Deterministic UTF-8 JSON over EXACTLY ``fields`` (missing keys fold in as ``null``).

    ``sort_keys=True`` + the compact ``(",", ":")`` separators make this reproducible across
    processes/runs for the same logical input — the same discipline Sentinel's
    ``hash_chain.canonical_json`` uses.
    """
    filtered = {field: data.get(field) for field in fields}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_row_hash(data: Mapping[str, Any], fields: tuple[str, ...]) -> str:
    """The lowercase 64-hex SHA-256 digest of ``data`` over ``fields``.

    Requires a non-empty ``prev_record_hash`` in ``data`` (the caller resolves it to the prior
    tip's ``content_hash`` or the record kind's GENESIS constant BEFORE calling this — there is
    no implicit genesis fallback here, so a chain-linking bug at the call site fails loudly
    instead of silently hashing a ``None`` link).
    """
    if not data.get("prev_record_hash"):
        raise ValueError(
            "compute_row_hash requires a non-empty prev_record_hash (the resolved tip or the "
            "record kind's GENESIS constant) — the caller must resolve the chain link first."
        )
    return hashlib.sha256(canonical_json(data, fields)).hexdigest()


def verify_row_hash(data: Mapping[str, Any], fields: tuple[str, ...], expected_hash: str) -> bool:
    """True iff recomputing the hash over ``data``/``fields`` matches ``expected_hash``."""
    return compute_row_hash(data, fields) == expected_hash
