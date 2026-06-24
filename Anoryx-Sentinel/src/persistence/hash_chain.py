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

F-014 BACKWARD-COMPATIBLE actor_id RULE (ADR-0017 §10 D9):
  actor_id is NOT in CANONICAL_FIELDS.  Instead, canonical_json() conditionally
  includes it ONLY WHEN the value is not None:

      if data.get("actor_id") is not None:
          filtered["actor_id"] = data["actor_id"]

  Rationale for the opt-in-when-present design:
  * Backward compatibility: every pre-F-014 row and every new non-operator event
    has actor_id=None (absent from the data dict or explicitly None). Their
    canonical JSON is IDENTICAL to the pre-F-014 form — no "actor_id":null key
    appears — so all stored hashes remain valid and validate_chain() passes over
    the full historical chain without any recalculation.
  * Tamper-evident when present: a row that WAS written with a non-null actor_id
    includes that UUID in its stored hash. If an attacker later nulls actor_id
    (or changes it to a different value), the recomputed canonical JSON no longer
    matches the stored row_hash — the chain breaks at that row, detected
    immediately by validate_chain().
  * Omission-detection: a row whose actor_id was present at write time CANNOT be
    silently stripped without breaking verification. The stored hash binds the
    original actor_id value.

  NOTE: adding actor_id to CANONICAL_FIELDS would instead produce
  "actor_id":null in EVERY pre-F-014 row's recomputed canonical JSON — changing
  their hashes and breaking validate_chain over all existing data. This was
  explicitly rejected (see ADR-0017 §10 D9 discussion).
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
    # routing_decision variant (F-006, ADR-0008 §5.6) — appended in a fixed,
    # documented position immediately before the chain fields. action_taken
    # (already present above) is reused by this variant.
    "selected_provider",
    "routing_reason",
    "outcome",
    "attempt_index",
    "requested_model",
    # F-007 (ADR-0010 §8) variant fields — appended in a fixed, documented position
    # immediately before the chain fields. action_taken / classifier_score /
    # rule_matched / tokens_in / tokens_out / cost_estimate_cents / latency_ms /
    # selected_provider / detected_endpoint / traffic_volume / first_seen_at (above)
    # are reused by the F-007 variants.
    "judge_score",
    "judge_confidence",
    "final_score",
    "judge_model",
    "judge_preset",
    "judge_outcome",
    "audit_mode",
    "classifier_reason",
    # Chain fields — must be last to surface ordering issues clearly.
    "prev_hash",
]


def canonical_json(data: dict[str, Any]) -> bytes:
    """Serialize data to canonical JSON: sorted keys, no whitespace, UTF-8.

    Only keys in CANONICAL_FIELDS are included.  Missing keys produce a None
    value in the output to prevent omission attacks.  Keys are serialized in
    alphabetical order (sort_keys=True) for determinism.

    F-014 actor_id opt-in-when-present rule (ADR-0017 §10 D9):
    actor_id is NOT in CANONICAL_FIELDS.  It is appended to the filtered dict
    ONLY when data["actor_id"] is not None.  This preserves the exact canonical
    form for all pre-F-014 rows (actor_id absent or None → no "actor_id" key in
    the JSON → stored hashes unchanged → validate_chain() continues to pass over
    historical data).  Rows written with a non-null actor_id bind that value
    into their hash: changing or nulling actor_id post-write breaks verification.
    """
    filtered: dict[str, Any] = {k: data.get(k) for k in CANONICAL_FIELDS}
    # Conditionally include actor_id — present only when explicitly set (non-None).
    # Must NOT be added to CANONICAL_FIELDS (that would inject "actor_id":null
    # into every historical row's recomputed hash and break the chain).
    if data.get("actor_id") is not None:
        filtered["actor_id"] = data["actor_id"]
    # F-018 (ADR-0021 §7): the shadow_ai_candidate_detected variant fields follow
    # the SAME opt-in-when-present rule as actor_id. They are NOT in CANONICAL_FIELDS;
    # each is appended ONLY when set (non-None). Every pre-F-018 row and every
    # non-candidate event has these absent/None, so its canonical JSON is byte-for-byte
    # the pre-F-018 form — stored hashes stay valid and validate_chain() passes over
    # all historical data. A candidate row binds its band/signals/key into the hash:
    # altering them post-write breaks verification (tamper-evident when present).
    for _f018_field in ("confidence_band", "fired_signals", "candidate_key"):
        if data.get(_f018_field) is not None:
            filtered[_f018_field] = data[_f018_field]
    # F-020 (ADR-0023 §5.4): webhook_provider, failure_class, and config_action follow
    # the SAME opt-in-when-present rule as actor_id / F-018 fields. None of them are in
    # CANONICAL_FIELDS; each is appended ONLY when set (non-None). Every pre-F-020 row
    # and every non-webhook event has all three as None, so their canonical JSON is
    # byte-for-byte the pre-F-020 form — stored hashes stay valid across the full
    # historical chain.
    # - webhook_provider: stable provider label bound into the hash on all webhook events.
    #   Changing or nulling it post-write breaks verification (tamper-evident when present).
    # - failure_class: terminal failure classification on webhook_delivery_failed events.
    #   Immutable terminal value — binding it gives tamper-evidence over the failure reason.
    # - config_action: CRUD verb on webhook_config_updated events. Immutable terminal value.
    # - delivery_attempts is NOT hash-folded — it is a mutable bounded counter; see the
    #   comment in audit_log_repository._row_to_hash_data() for the rationale.
    if data.get("webhook_provider") is not None:
        filtered["webhook_provider"] = data["webhook_provider"]
    if data.get("failure_class") is not None:
        filtered["failure_class"] = data["failure_class"]
    if data.get("config_action") is not None:
        filtered["config_action"] = data["config_action"]
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
