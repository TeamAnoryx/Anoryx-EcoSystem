"""Hash-chain utilities for the tamper-evident events_audit_log (F-003).

Canonical JSON: sorted keys, no whitespace (separators (',',':')), UTF-8.
The fields included in the hash are documented in ADR-0004 and listed in
CANONICAL_FIELDS.  event_timestamp and prev_hash are always in the hash
content to prevent reordering attacks.

Canonical form is deterministic because sort_keys=True is used.  CANONICAL_FIELDS
defines which fields are included; missing fields produce a None value (not
omission) to prevent omission attacks.  The JSON key order in the serialized
bytes is alphabetical (sort_keys=True) regardless of the order of CANONICAL_FIELDS.

GENESIS_HASH is the prev_hash of the first row in the chain. It is the
SHA-256 of the domain-separation string "anoryx-sentinel:events:genesis:v1"
(UTF-8, no newline), making it reproducible and documented.

Column names in CANONICAL_FIELDS match contracts/events.schema.json exactly:
  severity  — PiiBlockedEvent.severity (NOT pii_severity)
  status    — ComplianceCheckedEvent.status (NOT compliance_status)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# Domain-separation genesis constant.
# SHA-256("anoryx-sentinel:events:genesis:v1") — UTF-8, no trailing newline.
GENESIS_HASH = hashlib.sha256(b"anoryx-sentinel:events:genesis:v1").hexdigest()

# Fields included in the canonical hash content.
# event_timestamp and prev_hash are REQUIRED in the hash to prevent reordering.
# The repository passes these exact field names when computing row_hash.
# Column names must match contracts/events.schema.json field names exactly.
CANONICAL_FIELDS = [
    "event_id",
    "event_type",
    "event_timestamp",
    "request_id",
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
    # variant-specific fields (None values are included to prevent omission attacks)
    "model",
    "tokens_in",
    "tokens_out",
    "latency_ms",
    "cost_estimate_cents",
    "pattern_name",
    "severity",  # pii_blocked — matches events.schema.json PiiBlockedEvent.severity
    "action_taken",
    "classifier_score",
    "rule_matched",
    "secret_type",
    "direction",
    "policy_id",
    "violation_type",
    "framework",
    "control_id",
    "status",  # ComplianceCheckedEvent.status (F-002)
    "detected_endpoint",
    "traffic_volume",
    "first_seen_at",
    # Chain fields — must be last to surface ordering issues clearly.
    "prev_hash",
]


def canonical_json(data: dict[str, Any]) -> bytes:
    """Serialize data to canonical JSON: sorted keys, no whitespace, UTF-8.

    Only keys in CANONICAL_FIELDS are included.  Missing keys produce a None
    value in the output to prevent omission attacks.  Keys are serialized in
    alphabetical order (sort_keys=True) for determinism.
    """
    filtered: dict[str, Any] = {k: data.get(k) for k in CANONICAL_FIELDS}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_row_hash(data: dict[str, Any]) -> str:
    """Compute the SHA-256 hex digest of the canonical JSON of row data.

    data must include 'prev_hash' and 'event_timestamp'.
    Returns the 64-char lowercase hex string.
    """
    if "prev_hash" not in data:
        raise ValueError("row data must include 'prev_hash' to compute row_hash")
    if "event_timestamp" not in data:
        raise ValueError("row data must include 'event_timestamp' to compute row_hash")
    payload = canonical_json(data)
    return hashlib.sha256(payload).hexdigest()


def verify_row_hash(row_data: dict[str, Any], stored_hash: str) -> bool:
    """Recompute and compare the row_hash for a single row.

    Returns True if the recomputed hash matches stored_hash.
    """
    recomputed = compute_row_hash(row_data)
    return recomputed == stored_hash
