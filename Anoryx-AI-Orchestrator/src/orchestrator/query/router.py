"""GET /v1/events + /v1/bus/dlq + /v1/bus/schema-versions — the O-006 read seams (ADR-0006).

Implements the query/bus read seams the O-001/O-002 contract specified but never built. Each
tenant-scoped seam derives the caller's per-tenant principal (require_tenant_principal), opens
`get_tenant_session(principal)` so RLS structurally scopes the read (the tenant session
AUTOBEGINS — NEVER a nested `session.begin()`; ADR-0026), and returns ONLY the contract's
metadata projection (never `payload`, never the DLQ `original_envelope`). Results are cursor-
paginated and Limit-bounded exactly to the contract.

`GET /v1/bus/schema-versions` is auth-gated (a valid per-tenant token) but GLOBAL — it is the
version-negotiation allow-list (config), not tenant data (honesty boundary, ADR-0006).
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from orchestrator.config import SUPPORTED_SCHEMA_VERSIONS
from orchestrator.persistence.database import get_tenant_session
from orchestrator.persistence.repositories import list_dead_letters, list_events
from orchestrator.security import require_tenant_principal

router = APIRouter()

# The envelope schema $id this contract version pins (openapi.yaml SchemaVersions.envelope_schema_id
# const). Mirrors event-envelope.schema.json $id.
_ENVELOPE_SCHEMA_ID = "anoryx:event-envelope:v1"

# Limit bounds mirror the contract `Limit` parameter (min 1, max 200, default 50). Out-of-range
# values are CLAMPED (not 422'd) so the seam stays within its documented 200/401/403 responses.
_DEFAULT_LIMIT = 50
_MIN_LIMIT = 1
_MAX_LIMIT = 200

# Signed 64-bit range. An events cursor decodes to a `sequence_number` compared against a BIGINT
# column; a value outside this range would raise a DB DataError at query time (→ the app's 503
# catch-all), so it is validated in the decoder and mapped to the contract's 422 instead.
_BIGINT_MIN = -9223372036854775808
_BIGINT_MAX = 9223372036854775807

# The contract `Cursor` parameter caps opaque cursors at 512 chars (openapi.yaml Cursor.maxLength).
_MAX_CURSOR_LENGTH = 512


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _clamp_limit(raw: int | None) -> int:
    """Clamp a requested limit into [1, 200], defaulting to 50 when absent (contract `Limit`)."""
    if raw is None:
        return _DEFAULT_LIMIT
    if raw < _MIN_LIMIT:
        return _MIN_LIMIT
    if raw > _MAX_LIMIT:
        return _MAX_LIMIT
    return raw


def _encode_seq_cursor(sequence_number: int) -> str:
    """Opaque cursor for /v1/events (base64url of the sequence_number)."""
    return base64.urlsafe_b64encode(str(sequence_number).encode("utf-8")).decode("ascii")


def _decode_seq_cursor(cursor: str) -> int:
    """Decode a /v1/events cursor → sequence_number.

    Raises ValueError / binascii.Error / TypeError on a malformed cursor: non-base64 input, text
    that is not an integer, or an integer OUTSIDE the signed BIGINT range (which the DB would
    otherwise reject with a DataError). The call site maps all of these to a 422, never a 503.
    """
    value = int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    if not (_BIGINT_MIN <= value <= _BIGINT_MAX):
        raise ValueError("cursor sequence_number is outside the signed BIGINT range")
    return value


def _encode_dlq_cursor(created_at: Any, dlq_id: str) -> str:
    """Opaque cursor for /v1/bus/dlq (base64url of the (created_at, dlq_id) sort key)."""
    payload = json.dumps({"c": created_at.isoformat(), "d": dlq_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def _decode_dlq_cursor(cursor: str) -> tuple[str, str]:
    """Decode a /v1/bus/dlq cursor → (created_at, dlq_id).

    Raises ValueError / KeyError / TypeError / binascii.Error on a malformed cursor: non-base64
    input, JSON that is not an object (`[1,2]` / `5` → `obj["c"]` raises TypeError), a missing
    key, or a `c` value that is not a parseable ISO-8601 timestamp. The timestamp is pre-parsed
    here (not at query time) so a bad value is a 422, never a DB DataError → 503.
    """
    obj = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("dlq cursor is not a JSON object")
    created_at = obj["c"]
    dlq_id = obj["d"]
    # Normalize/validate the timestamp before the query. A non-str or unparseable value raises
    # TypeError/ValueError here (→ 422) instead of a CAST(... AS timestamptz) DataError (→ 503).
    datetime.fromisoformat(created_at)
    return created_at, dlq_id


def _event_metadata_body(row: dict[str, Any]) -> dict[str, Any]:
    """Project one ingest_events row to EventMetadata (allow-list; NEVER `payload`)."""
    body: dict[str, Any] = {
        "event_id": row["event_id"],
        "event_type": row["event_type"],
        "event_timestamp": row["event_timestamp"],
        "tenant_id": row["tenant_id"],
        "team_id": row["team_id"],
        "project_id": row["project_id"],
        "agent_id": row["agent_id"],
    }
    if row.get("request_id") is not None:
        body["request_id"] = row["request_id"]
    return body


def _dead_letter_metadata_body(row: dict[str, Any]) -> dict[str, Any]:
    """Project one dead_letter_queue row to DeadLetterMetadata (NEVER `original_envelope`).

    `source_sequence` maps to the contract's required `sequence`; a NULL (unreachable for a
    tenant-visible row — a payload-invalid row is NULL-tenant and RLS-hidden) is coerced to 0
    so the response stays contract-conformant.
    """
    sequence = row.get("source_sequence")
    return {
        "dlq_id": row["dlq_id"],
        "reason": row["reason"],
        "attempt_count": row["attempt_count"],
        "first_failed_at": row["first_failed_at"],
        "event_type": row["event_type"],
        "source_product": row["source_product"],
        "sequence": sequence if sequence is not None else 0,
    }


@router.get("/v1/events")
async def query_events(
    principal: str = Depends(require_tenant_principal),
    tenant_id: str | None = Query(default=None),
    team_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=_MAX_CURSOR_LENGTH),
) -> JSONResponse:
    """Metadata-only, cursor-paginated ingested-event query (tenant-scoped by the principal).

    An A token may not even ASK for B: a `tenant_id` filter that differs from the principal is
    a 403 (Fork C — RLS would also return empty, but the explicit reject matches the contract's
    per-tenant authorization). Reads run under the principal's RLS session; the projection is
    EventMetadata only (never `payload`).
    """
    request_id = _request_id()
    # Wire UUIDs are case-insensitive hex; compare case-folded so an identical tenant in a
    # different case is NOT spuriously 403'd. Fail-closed semantics are unchanged (a genuinely
    # different tenant still rejects).
    if tenant_id is not None and tenant_id.lower() != principal.lower():
        return _error(
            403,
            "forbidden",
            "tenant_id filter does not match the authenticated principal",
            request_id,
        )
    limit_value = _clamp_limit(limit)
    decoded_cursor: int | None = None
    if cursor is not None:
        try:
            decoded_cursor = _decode_seq_cursor(cursor)
        except (ValueError, KeyError, TypeError, binascii.Error):
            return _error(422, "schema_invalid", "cursor is malformed", request_id)
    filters = {
        "tenant_id": tenant_id,
        "team_id": team_id,
        "agent_id": agent_id,
        "event_type": event_type,
        "since": since,
        "until": until,
    }
    async with get_tenant_session(principal) as session:
        rows, next_seq = await list_events(
            session, filters=filters, limit=limit_value, cursor=decoded_cursor
        )
    body = {
        "data": [_event_metadata_body(row) for row in rows],
        "next_cursor": _encode_seq_cursor(next_seq) if next_seq is not None else None,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


@router.get("/v1/bus/dlq")
async def query_dead_letters(
    principal: str = Depends(require_tenant_principal),
    reason: str | None = Query(default=None),
    source_product: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=_MAX_CURSOR_LENGTH),
) -> JSONResponse:
    """Metadata-only, cursor-paginated dead-letter query (tenant-scoped by the principal).

    Reads run under the principal's RLS session, which hides NULL-tenant (payload-invalid,
    operator-only) rows from every tenant. The projection is DeadLetterMetadata only — NEVER the
    preserved `original_envelope` (re-driving a full DLQ record is replay-from-DLQ, not a read).
    """
    request_id = _request_id()
    limit_value = _clamp_limit(limit)
    decoded_cursor: tuple[str, str] | None = None
    if cursor is not None:
        try:
            decoded_cursor = _decode_dlq_cursor(cursor)
        except (ValueError, KeyError, TypeError, binascii.Error):
            return _error(422, "schema_invalid", "cursor is malformed", request_id)
    filters = {
        "reason": reason,
        "source_product": source_product,
        "since": since,
        "until": until,
    }
    async with get_tenant_session(principal) as session:
        rows, next_key = await list_dead_letters(
            session, filters=filters, limit=limit_value, cursor=decoded_cursor
        )
    body = {
        "data": [_dead_letter_metadata_body(row) for row in rows],
        "next_cursor": (
            _encode_dlq_cursor(next_key[0], next_key[1]) if next_key is not None else None
        ),
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


@router.get("/v1/bus/schema-versions")
async def get_schema_versions(
    principal: str = Depends(require_tenant_principal),
) -> JSONResponse:
    """The supported envelope schema versions (auth-gated but GLOBAL — config, not tenant data).

    Requires a valid per-tenant token (auth-gated) but is NOT tenant-scoped: it is the
    version-negotiation allow-list backing the reject-to-DLQ rule, identical for every caller
    (honesty boundary, ADR-0006). `principal` is required for auth only; it does not scope.
    """
    request_id = _request_id()
    body = {
        "supported": sorted(SUPPORTED_SCHEMA_VERSIONS),
        "envelope_schema_id": _ENVELOPE_SCHEMA_ID,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})
