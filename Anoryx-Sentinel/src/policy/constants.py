"""Shared constants for the F-008 policy layer (ADR-0009).

WILDCARD_UUID is DUAL-PURPOSE (ADR-0009 Decisions A + B):
  (a) sub-tenant wildcard token for model policies — team_id / project_id ONLY;
  (b) SYSTEM_TENANT_ID — the audit-row owner for pre-verification rejections
      (schema-invalid / signature-failed records have no resolvable tenant).
tenant_id may NEVER be the wildcard — a wildcard tenant is cross-tenant blast
radius and a privilege escalation if the signing key leaks (threat vector #16).

agent_id is a lowercase slug in the contract (not a UUID), so its wildcard token
is the reserved slug WILDCARD_AGENT ("all-agents"), not the zero-UUID.

The seven event_type names below MUST stay consistent across the four sites
(this module, persistence.models.events_audit_log.VALID_EVENT_TYPES +
ACTION_TAKEN_BY_EVENT_TYPE, the ck_eal_event_type CHECK constraint, and
contracts/events.schema.json) — the F-006 routing_decision 4-site rule.
"""

from __future__ import annotations

# --- Wildcard / system sentinel identifiers ---
WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"
WILDCARD_AGENT = "all-agents"
SYSTEM_TENANT_ID = WILDCARD_UUID  # audit owner for schema / signature-fail rejections
GATEWAY_AGENT = "gateway-core"  # emitting-component slug for system / enforcement events

# --- F-008 event_type names (4-site consistency target) ---
EVT_INTAKE_ACCEPTED = "policy_intake_accepted"
EVT_INTAKE_REJECTED_SIGNATURE = "policy_intake_rejected_signature"
EVT_INTAKE_REJECTED_SCOPE_MISMATCH = "policy_intake_rejected_scope_mismatch"
EVT_INTAKE_REJECTED_REPLAY = "policy_intake_rejected_replay"
EVT_INTAKE_REJECTED_SCHEMA = "policy_intake_rejected_schema"
EVT_DECISION_ALLOW = "policy_decision_allow"
EVT_DECISION_DENY = "policy_decision_deny"

POLICY_EVENT_TYPES = frozenset(
    {
        EVT_INTAKE_ACCEPTED,
        EVT_INTAKE_REJECTED_SIGNATURE,
        EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
        EVT_INTAKE_REJECTED_REPLAY,
        EVT_INTAKE_REJECTED_SCHEMA,
        EVT_DECISION_ALLOW,
        EVT_DECISION_DENY,
    }
)

# --- Signed-claims field set (ADR-0009 §2) ---
# These eight fields are the AUTHORITATIVE scope carried inside the JWS payload
# and cross-checked against the (untrusted) record body (scope-resolve-and-reject).
SIGNED_CLAIM_FIELDS = (
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
    "policy_id",
    "policy_version",
    "effective_from",
    "policy_type",
)

# The signed claims ALSO carry a SHA-256 hash (hex) of the canonical full record
# (every field except `signature`). The eight scope claims above do NOT cover the
# enforcement-determining fields (denied/allowed_model_ids, max_*_per_period,
# period, scope, reason, effective_until); this hash binds the ENTIRE record to the
# signature so tampering any field after signing is detected at intake. Kept as a
# hash (not the full record) so the signed payload stays within the contract's
# signature maxLength (4096) even for a 512-entry model list. Makes the contract's
# "signature over the policy record" literal (ADR-0009 §2 / events-side has none).
CONTENT_HASH_CLAIM = "policy_hash"

# Coarse pre-parse byte guard (DoS-via-inspection). The schema's per-field
# maxLength / maxItems do the precise bounding; this only stops a multi-MB blob
# from reaching the JSON parser / validator. A maximal allow-list (512 ids *
# 256 chars) stays well under this.
MAX_RECORD_BYTES = 1_048_576
