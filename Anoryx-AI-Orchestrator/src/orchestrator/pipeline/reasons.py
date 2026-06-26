"""DLQ reasons + dispositions for the ingest pipeline (O-003, ADR-0003).

The DLQ reason set is CLOSED by the O-002 contract (DeadLetterReason enum). The pipeline
maps each failure mode into it without inventing a reason — see the ADR's reason-mapping
table. The two envelope/payload coherence failures (event_type, idempotency_key) map to
PAYLOAD_SCHEMA_INVALID (malformed framing → the closest closed reason).
"""

from __future__ import annotations

# Closed DLQ reason set (mirrors contracts/openapi.yaml DeadLetterReason).
UNKNOWN_SCHEMA_VERSION = "unknown_schema_version"
PAYLOAD_SCHEMA_INVALID = "payload_schema_invalid"
SOURCE_IDENTITY_MISMATCH = "source_identity_mismatch"
IDEMPOTENCY_CONFLICT = "idempotency_conflict"
MAX_ATTEMPTS_EXCEEDED = "max_attempts_exceeded"

DLQ_REASONS = frozenset(
    {
        UNKNOWN_SCHEMA_VERSION,
        PAYLOAD_SCHEMA_INVALID,
        SOURCE_IDENTITY_MISMATCH,
        IDEMPOTENCY_CONFLICT,
        MAX_ATTEMPTS_EXCEEDED,
    }
)

# Audit-chain dispositions.
ACCEPTED = "accepted"
DEDUPED = "deduped"
DEAD_LETTERED = "dead_lettered"
