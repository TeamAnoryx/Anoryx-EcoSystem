"""Hash-chain utilities for the tamper-evident ingest_audit_log (O-003, ADR-0003).

Ported from Anoryx-Sentinel/src/persistence/hash_chain.py (F-003 / ADR-0004) — same
canonical-JSON discipline, adapted to the Orchestrator ingest-audit row shape.

Canonical JSON: sorted keys, no whitespace (separators (",",":")), UTF-8. The fields
folded into the hash are CANONICAL_FIELDS; missing fields produce a None value (not
omission) to prevent omission attacks. prev_hash and event_timestamp are ALWAYS in the
hash content to prevent reordering attacks.

GENESIS_HASH is the prev_hash of the first chain row: SHA-256 of the domain-separation
string "anoryx-orchestrator:ingest-audit:genesis:v1" (UTF-8, no newline) — reproducible
and documented, and distinct from Sentinel's genesis so the two chains can never be
confused.

OPT-IN-WHEN-PRESENT rule (mirrors F-003's actor_id rule, ADR-0017 §10 D9):
  dlq_reason and dlq_id are NOT in CANONICAL_FIELDS. They are folded into the hash ONLY
  when the value is not None. An "accepted" row (both None) therefore hashes IDENTICALLY
  to the chain-without-them form — so the rule is backward-compatible by construction and
  a future column added the same way does not rewrite historical hashes. A dead-lettered
  row that WAS written with a non-null dlq_reason/dlq_id binds those values into its hash:
  altering or nulling them post-write breaks verify_row_hash (tamper-evident when present).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Domain-separated genesis constant. Distinct from Sentinel's genesis string.
GENESIS_HASH = hashlib.sha256(b"anoryx-orchestrator:ingest-audit:genesis:v1").hexdigest()

# Fields folded into the canonical hash content, in a fixed documented order.
# prev_hash MUST be last to surface ordering issues clearly; event_timestamp is
# required in the content to prevent reordering.
CANONICAL_FIELDS = [
    # Common F-002 event fields (carried so the chain binds attribution).
    "event_id",
    "event_type",
    "event_timestamp",
    "request_id",
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
    # Ingest-specific fields.
    "envelope_id",
    "idempotency_key",
    "source_product",
    "disposition",
    # Chain field — last.
    "prev_hash",
]

# Fields folded in ONLY when non-None (opt-in-when-present). Never add these to
# CANONICAL_FIELDS — that would inject "<field>":null into every accepted row and
# break verification over historical data.
_OPTIONAL_FIELDS = ("dlq_reason", "dlq_id")


def canonical_json(data: dict[str, Any]) -> bytes:
    """Serialize row data to canonical JSON: sorted keys, no whitespace, UTF-8.

    Only CANONICAL_FIELDS are included (missing → None, to prevent omission attacks).
    Each _OPTIONAL_FIELDS member is appended ONLY when data[field] is not None.
    """
    filtered: dict[str, Any] = {k: data.get(k) for k in CANONICAL_FIELDS}
    for field in _OPTIONAL_FIELDS:
        if data.get(field) is not None:
            filtered[field] = data[field]
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_row_hash(data: dict[str, Any]) -> str:
    """Return the 64-char lowercase SHA-256 hex digest of the canonical JSON of *data*.

    *data* MUST include 'prev_hash' and 'event_timestamp'.
    """
    if "prev_hash" not in data:
        raise ValueError("row data must include 'prev_hash' to compute row_hash")
    if "event_timestamp" not in data:
        raise ValueError("row data must include 'event_timestamp' to compute row_hash")
    return hashlib.sha256(canonical_json(data)).hexdigest()


def verify_row_hash(row_data: dict[str, Any], stored_hash: str) -> bool:
    """Recompute and compare the row_hash for a single row. True iff it matches."""
    return compute_row_hash(row_data) == stored_hash


# =========================================================================== #
# Distribution audit chain (O-004, ADR-0004) — ADDITIVE, parallel to the ingest
# chain above. Same canonicalization discipline over a distinct field set and a
# domain-separated genesis so the ingest and distribution chains can never be
# confused. The ingest constants/functions above are untouched (byte-identical).
# =========================================================================== #

# Domain-separated genesis constant, distinct from GENESIS_HASH and Sentinel's genesis.
DISTRIBUTION_GENESIS_HASH = hashlib.sha256(
    b"anoryx-orchestrator:distribution-audit:genesis:v1"
).hexdigest()

# Fields folded into the canonical hash content, in a fixed documented order.
# prev_hash MUST be last to surface ordering issues clearly.
DISTRIBUTION_CANONICAL_FIELDS = [
    "distribution_id",
    "policy_id",
    "tenant_id",
    "policy_type",
    "disposition",
    # Chain field — last.
    "prev_hash",
]

# Folded in ONLY when non-None (opt-in-when-present). Never add these to
# DISTRIBUTION_CANONICAL_FIELDS — that would inject "<field>":null into every link
# and break verification over historical data.
_DISTRIBUTION_OPTIONAL_FIELDS = ("sentinel_id", "error_reason")


def canonical_distribution_json(data: dict[str, Any]) -> bytes:
    """Serialize distribution row data to canonical JSON: sorted keys, no whitespace, UTF-8.

    Only DISTRIBUTION_CANONICAL_FIELDS are included (missing → None, to prevent omission
    attacks). Each _DISTRIBUTION_OPTIONAL_FIELDS member is appended ONLY when not None.
    """
    filtered: dict[str, Any] = {k: data.get(k) for k in DISTRIBUTION_CANONICAL_FIELDS}
    for field in _DISTRIBUTION_OPTIONAL_FIELDS:
        if data.get(field) is not None:
            filtered[field] = data[field]
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_distribution_row_hash(data: dict[str, Any]) -> str:
    """Return the 64-char lowercase SHA-256 hex digest of the canonical JSON of *data*.

    *data* MUST include 'prev_hash'.
    """
    if "prev_hash" not in data:
        raise ValueError("row data must include 'prev_hash' to compute row_hash")
    return hashlib.sha256(canonical_distribution_json(data)).hexdigest()


def verify_distribution_row_hash(row_data: dict[str, Any], stored_hash: str) -> bool:
    """Recompute and compare the distribution row_hash for a single row. True iff it matches."""
    return compute_distribution_row_hash(row_data) == stored_hash
