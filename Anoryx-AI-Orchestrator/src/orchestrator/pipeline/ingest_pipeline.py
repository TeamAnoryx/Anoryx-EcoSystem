"""The ingest pipeline — consumer obligations, dedup/persist, reject-to-DLQ (ADR-0003).

Runs AFTER the receiver's boundary checks (HMAC verified, envelope structurally valid).
Enforces, in order: schema-version allow-list → payload schema → source identity → the two
envelope/payload coherence invariants → dedup + persist. Any obligation failure is
reject-to-DLQ (a durable failure-envelope row + a dead_lettered chain link). An accept is
a tenant-scoped event+outbox write followed by an accepted chain link.

ADR-0026 discipline (no double-begin, no fail-open swallow):
  * get_tenant_session() AUTOBEGINS — its body is NEVER wrapped in session.begin().
  * The ONLY caught exception is IntegrityError (the expected concurrent-duplicate race on
    the UNIQUE idempotency_key). A logic defect (e.g. InvalidRequestError from a stray
    begin()) and any DB-connectivity error (OperationalError / OSError / pool TimeoutError)
    are NOT in that catch, so they PROPAGATE to a fail-safe BLOCK at the receiver (a 5xx;
    the at-least-once emitter retries). There is deliberately no fail-open degrade path on
    ingest — a non-durably-recorded event must not be 202'd.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError

from orchestrator.config import IngestSettings
from orchestrator.persistence import repositories as repo
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.pipeline import reasons
from orchestrator.schema_validation import payload_errors

# Payload-derived common fields the chain + dedup rows carry.
_COMMON_FIELDS = (
    "event_id",
    "event_type",
    "event_timestamp",
    "request_id",
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
)


@dataclass(frozen=True, slots=True)
class IngestResult:
    """The pipeline disposition for one envelope."""

    disposition: str  # reasons.ACCEPTED | DEDUPED | DEAD_LETTERED
    event_id: str  # echoed in the 202 (== envelope.idempotency_key)
    dlq_reason: str | None = None
    dlq_id: str | None = None


def _utcnow_z() -> str:
    """RFC 3339 UTC timestamp with a 'Z' suffix (matches the contract example style)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _content_hash(payload: Any) -> str:
    """Stable SHA-256 over the canonical JSON of the payload (benign-dup vs conflict)."""
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _extract_common(payload: Any) -> dict[str, str | None]:
    """Best-effort pull of the F-002 common fields from *payload* (str or None each)."""
    if not isinstance(payload, dict):
        return {field: None for field in _COMMON_FIELDS}
    out: dict[str, str | None] = {}
    for field in _COMMON_FIELDS:
        value = payload.get(field)
        out[field] = value if isinstance(value, str) else None
    return out


def _chain_fields(envelope: dict[str, Any], payload: Any) -> dict[str, Any]:
    """Build the audit-chain row fields. Envelope-derived fields are authoritative for
    classification; payload-derived fields are best-effort (None when unavailable)."""
    fields = _extract_common(payload)
    # Envelope-derived classification (always present after structural validation).
    fields["event_type"] = envelope["event_type"]
    fields["envelope_id"] = envelope["envelope_id"]
    fields["idempotency_key"] = envelope["idempotency_key"]
    fields["source_product"] = envelope["source_product"]
    return fields


async def _dead_letter(envelope: dict[str, Any], payload: Any, reason: str) -> IngestResult:
    """Persist a failure-envelope DLQ row + a dead_lettered chain link (privileged, atomic)."""
    dlq_id = str(uuid.uuid4())
    common = _extract_common(payload)
    dlq_row = {
        "dlq_id": dlq_id,
        "original_envelope": envelope,
        "reason": reason,
        "attempt_count": 1,
        "first_failed_at": _utcnow_z(),
        "event_type": envelope["event_type"],
        "source_product": envelope["source_product"],
        "source_sequence": envelope.get("sequence"),
        "tenant_id": common["tenant_id"],
    }
    chain_fields = _chain_fields(envelope, payload)
    async with get_privileged_session() as session:
        async with session.begin():
            await repo.insert_dead_letter(session, dlq_row)
            await repo.append_audit_link(
                session,
                chain_fields,
                disposition=reasons.DEAD_LETTERED,
                dlq_reason=reason,
                dlq_id=dlq_id,
            )
    return IngestResult(
        disposition=reasons.DEAD_LETTERED,
        event_id=envelope["idempotency_key"],
        dlq_reason=reason,
        dlq_id=dlq_id,
    )


async def _persist_or_dedup(
    *, tenant_id: str, idempotency_key: str, content_hash: str, event_row: dict, outbox_row: dict
) -> str:
    """Insert the event + outbox, or detect a duplicate. Returns a disposition token:
    reasons.ACCEPTED, reasons.DEDUPED, or reasons.IDEMPOTENCY_CONFLICT.

    Tenant session (autobegin; NO session.begin()). The UNIQUE idempotency_key is the
    dedup gate. The common re-delivery case is resolved by the same-tenant existence
    check; the rare unique-violation (concurrent insert / cross-tenant forgery) is
    resolved globally via a privileged content_hash lookup.
    """
    async with get_tenant_session(tenant_id) as session:
        existing = await repo.tenant_event_content_hash(session, idempotency_key)
        if existing is not None:
            return reasons.DEDUPED if existing == content_hash else reasons.IDEMPOTENCY_CONFLICT
        try:
            await repo.insert_ingest_event(session, event_row)
            await repo.insert_forward_outbox(
                session,
                outbox_id=outbox_row["id"],
                tenant_id=outbox_row["tenant_id"],
                event_id=outbox_row["event_id"],
                idempotency_key=outbox_row["idempotency_key"],
            )
            await session.commit()
            return reasons.ACCEPTED
        except IntegrityError:
            # Concurrent duplicate or cross-tenant key collision. Roll back the failed
            # autobegun transaction; resolve benign-vs-conflict globally (privileged).
            await session.rollback()

    async with get_privileged_session() as session:
        other = await repo.privileged_event_content_hash(session, idempotency_key)
    return reasons.DEDUPED if other == content_hash else reasons.IDEMPOTENCY_CONFLICT


async def process_envelope(envelope: dict[str, Any], *, settings: IngestSettings) -> IngestResult:
    """Run the ingest pipeline for one structurally-valid, HMAC-verified envelope.

    `settings.ingest_peer_source_product` is the authenticated peer identity (the trusted
    source_product); `settings.supported_schema_versions` is the reject-to-DLQ allow-list.
    """
    payload = envelope.get("payload")
    echo = envelope["idempotency_key"]

    # 1. schema-version allow-list (do NOT best-effort-parse an unknown shape).
    if envelope["schema_version"] not in settings.supported_schema_versions:
        return await _dead_letter(envelope, payload, reasons.UNKNOWN_SCHEMA_VERSION)

    # 2. payload validates against the locked events.schema.json (unmodified).
    if payload_errors(payload):
        return await _dead_letter(envelope, payload, reasons.PAYLOAD_SCHEMA_INVALID)

    # 3. source identity: body source_product must equal the authenticated peer.
    if envelope["source_product"] != settings.ingest_peer_source_product:
        return await _dead_letter(envelope, payload, reasons.SOURCE_IDENTITY_MISMATCH)

    # 4 & 5. envelope/payload coherence invariants.
    if envelope["event_type"] != payload.get("event_type"):
        return await _dead_letter(envelope, payload, reasons.PAYLOAD_SCHEMA_INVALID)
    if echo != payload.get("event_id"):
        return await _dead_letter(envelope, payload, reasons.PAYLOAD_SCHEMA_INVALID)

    # 6. dedup + persist (tenant-scoped).
    tenant_id = payload["tenant_id"]
    content_hash = _content_hash(payload)
    common = _extract_common(payload)
    event_row = {
        "envelope_id": envelope["envelope_id"],
        "idempotency_key": echo,
        "source_product": envelope["source_product"],
        "source_sequence": envelope["sequence"],
        "schema_version": envelope["schema_version"],
        "occurred_at": envelope["occurred_at"],
        "correlation_id": envelope["correlation_id"],
        "causation_id": envelope.get("causation_id"),
        "payload": payload,
        "content_hash": content_hash,
        **common,
    }
    outbox_row = {
        "id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "event_id": payload["event_id"],
        "idempotency_key": echo,
    }
    disposition = await _persist_or_dedup(
        tenant_id=tenant_id,
        idempotency_key=echo,
        content_hash=content_hash,
        event_row=event_row,
        outbox_row=outbox_row,
    )

    if disposition == reasons.DEDUPED:
        # Benign duplicate — at-least-once; no second row, no new chain link (the chain
        # records the FIRST acceptance; appending per duplicate would grow it unbounded).
        return IngestResult(disposition=reasons.DEDUPED, event_id=echo)
    if disposition == reasons.IDEMPOTENCY_CONFLICT:
        return await _dead_letter(envelope, payload, reasons.IDEMPOTENCY_CONFLICT)

    # ACCEPTED → append the accepted chain link (privileged, atomic).
    chain_fields = _chain_fields(envelope, payload)
    async with get_privileged_session() as session:
        async with session.begin():
            await repo.append_audit_link(session, chain_fields, disposition=reasons.ACCEPTED)
    return IngestResult(disposition=reasons.ACCEPTED, event_id=echo)
