"""POST /v1/messaging/messages, GET /v1/messaging/inbox/..., PUT/GET /v1/state/{state_key}
(O-012, ADR-0012).

Two independent, intra-tenant, Postgres-backed seams, both gated by the EXISTING
`require_tenant_principal` dependency from security.py — the SAME credential already
gating `/v1/events`, `/v1/identity/events`, and `/v1/automation/rules`. No new trust root.

A. Agent mailbox relay — durable, ordered, POLL-BASED (never push). `message_type` is a
   free-text label the sender chooses, bounded length — purely descriptive metadata, NEVER
   interpreted, parsed, or executed here. `body` is an OPAQUE JSONB payload, relayed
   byte-for-byte — the Orchestrator never inspects or acts on its contents, unlike O-011's
   automation matcher, which deliberately DOES inspect event payloads.

B. Shared key-value state store, OPTIMISTIC CONCURRENCY (compare-and-swap via a version
   number) — NOT distributed consensus, NOT "flawless" cross-product sync. A single
   Postgres instance's row is the sole source of truth for a key's current version.

Validation order at the message-send boundary (each a 422 with a distinct code — never a
5xx for an ordinary validation failure): unknown fields -> schema_invalid; a deeply-nested
body can raise RecursionError from json.loads() or the contains_nul() recursive walk before
any further validation runs — both call sites catch RecursionError narrowly and return 422
schema_invalid (mirrors automation/router.py's exact handling of this, read there first);
missing/wrong-typed field -> schema_invalid; oversized `body` (serialized bytes over
ORCH_MESSAGING_MAX_BODY_BYTES) -> body_too_large; NUL anywhere in the request -> schema_invalid
(reuses boundary.contains_nul, never reinvented).

The state-write boundary mirrors this shape for `value` (oversized -> state_value_too_large),
plus its own expected_version type/shape checks.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from orchestrator.boundary import contains_nul
from orchestrator.config import MessagingSettings
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_messaging_audit_link,
    append_state_audit_link,
    create_agent_state_if_absent,
    get_agent_message_by_idempotency_key,
    get_agent_state,
    insert_agent_message,
    list_inbox_messages,
    update_agent_state_cas,
)
from orchestrator.security import require_tenant_principal

router = APIRouter()

_ALLOWED_SEND_KEYS = frozenset(
    {
        "sender_team_id",
        "sender_project_id",
        "sender_agent_id",
        "recipient_team_id",
        "recipient_project_id",
        "recipient_agent_id",
        "message_type",
        "body",
        "idempotency_key",
    }
)
_STABLE_ID_FIELDS = (
    "sender_team_id",
    "sender_project_id",
    "sender_agent_id",
    "recipient_team_id",
    "recipient_project_id",
    "recipient_agent_id",
)
_MAX_STABLE_ID_LEN = 64
_MAX_MESSAGE_TYPE_LEN = 64
_MAX_IDEMPOTENCY_KEY_LEN = 128

_ALLOWED_STATE_KEYS = frozenset({"expected_version", "value", "updated_by_agent_id"})
_MAX_UPDATED_BY_AGENT_ID_LEN = 64

_DEFAULT_INBOX_LIMIT = 50
_MIN_INBOX_LIMIT = 1
_BIGINT_MIN = -9223372036854775808
_BIGINT_MAX = 9223372036854775807


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _isoformat(value: object) -> object:
    return value.isoformat() if isinstance(value, datetime) else value


async def _parse_body(
    request: Request, request_id: str
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Parse + NUL-check the raw request body. Returns (body, None) or (None, error_response).

    RecursionError from a deeply-nested body can be raised by EITHER json.loads() or the
    recursive contains_nul() walk — both are caught narrowly here and mapped to the SAME
    422 schema_invalid outcome, never an uncaught 500 (mirrors automation/router.py verbatim).
    """
    raw_body = await request.body()
    try:
        parsed = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return None, _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(parsed, dict):
        return None, _error(422, "schema_invalid", "request body must be a JSON object", request_id)
    try:
        has_forbidden_nul = contains_nul(parsed)
    except RecursionError:
        return None, _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if has_forbidden_nul:
        return None, _error(
            422, "schema_invalid", "request contains a forbidden NUL character", request_id
        )
    return parsed, None


def _message_body(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence_number": row["sequence_number"],
        "tenant_id": row["tenant_id"],
        "sender_team_id": row["sender_team_id"],
        "sender_project_id": row["sender_project_id"],
        "sender_agent_id": row["sender_agent_id"],
        "recipient_team_id": row["recipient_team_id"],
        "recipient_project_id": row["recipient_project_id"],
        "recipient_agent_id": row["recipient_agent_id"],
        "message_type": row["message_type"],
        "body": row["body"],
        "idempotency_key": row["idempotency_key"],
        "created_at": _isoformat(row["created_at"]),
    }


def _validate_send_body(
    body: dict[str, Any], settings: MessagingSettings
) -> tuple[str, str] | None:
    """Structural + bounds validation of a POST /v1/messaging/messages body.

    Returns (code, message) for a 422, or None when valid. Never touches the DB.
    """
    if set(body) - _ALLOWED_SEND_KEYS:
        return ("schema_invalid", "request contains unknown fields")
    if _ALLOWED_SEND_KEYS - set(body):
        return ("schema_invalid", "request is missing required fields")

    for field in _STABLE_ID_FIELDS:
        value = body.get(field)
        if not isinstance(value, str) or not value or len(value) > _MAX_STABLE_ID_LEN:
            return ("schema_invalid", f"{field} is required")

    message_type = body.get("message_type")
    if (
        not isinstance(message_type, str)
        or not message_type
        or len(message_type) > _MAX_MESSAGE_TYPE_LEN
    ):
        return ("schema_invalid", "message_type is required")

    idempotency_key = body.get("idempotency_key")
    if (
        not isinstance(idempotency_key, str)
        or not idempotency_key
        or len(idempotency_key) > _MAX_IDEMPOTENCY_KEY_LEN
    ):
        return ("schema_invalid", "idempotency_key is required")

    message_body = body.get("body")
    # The DB CHECK constraint (ck_am_body_is_object) requires a JSON OBJECT — enforced here
    # too so a malformed body 422s at the boundary rather than 503-ing on a CHECK violation.
    if not isinstance(message_body, dict):
        return ("schema_invalid", "body must be a JSON object")
    try:
        serialized_size = len(json.dumps(message_body).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return ("schema_invalid", "body is not serializable")
    if serialized_size > settings.max_message_body_bytes:
        return (
            "body_too_large",
            f"body may be at most {settings.max_message_body_bytes} bytes serialized",
        )

    return None


@router.post("/v1/messaging/messages")
async def send_message(
    request: Request, principal: str = Depends(require_tenant_principal)
) -> JSONResponse:
    """Send one agent-to-agent message (durable, ordered, poll-based — NOT push).

    Idempotent: a resend with the same idempotency_key is NOT an error — it is an
    idempotent no-op that returns the ORIGINAL message's sequence_number/created_at
    unchanged (`disposition: "deduped"`). Both a fresh send AND a deduped resend are
    hash-chain audited (ADR-0012; contrast with the state-write seam below).
    """
    request_id = _request_id()
    settings: MessagingSettings = request.app.state.messaging_settings

    body, error = await _parse_body(request, request_id)
    if error is not None:
        return error
    if body is None:
        # Unreachable: _parse_body's contract guarantees body is set when error is None.
        raise RuntimeError("_parse_body returned neither a body nor an error")

    structural = _validate_send_body(body, settings)
    if structural is not None:
        code, message = structural
        return _error(422, code, message, request_id)

    row = {
        "tenant_id": principal,
        "sender_team_id": body["sender_team_id"],
        "sender_project_id": body["sender_project_id"],
        "sender_agent_id": body["sender_agent_id"],
        "recipient_team_id": body["recipient_team_id"],
        "recipient_project_id": body["recipient_project_id"],
        "recipient_agent_id": body["recipient_agent_id"],
        "message_type": body["message_type"],
        "body": body["body"],
        "idempotency_key": body["idempotency_key"],
    }

    result_row: dict[str, Any] | None
    async with get_tenant_session(principal) as session:
        try:
            result_row = await insert_agent_message(session, row)
            await session.commit()
            disposition = "sent"
        except IntegrityError:
            # Concurrent/duplicate send with the SAME (tenant_id, idempotency_key). Roll
            # back the failed autobegun transaction; re-fetch on a FRESH tenant session
            # below (this one's transaction-local tenant GUC is gone after rollback).
            await session.rollback()
            result_row = None
            disposition = "deduped"

    if result_row is None:
        async with get_tenant_session(principal) as session:
            result_row = await get_agent_message_by_idempotency_key(
                session, body["idempotency_key"]
            )
        if result_row is None:
            # UNIQUE(tenant_id, idempotency_key) means a conflict can only be with THIS
            # tenant's own row — it must exist. Unreachable in practice; a defensive
            # fail-safe rather than a silent None-body 202.
            raise RuntimeError("agent_messages dedup conflict but no existing row found")

    async with get_privileged_session() as psession:
        async with psession.begin():
            await append_messaging_audit_link(
                psession,
                tenant_id=principal,
                sender_agent_id=row["sender_agent_id"],
                recipient_agent_id=row["recipient_agent_id"],
                message_type=row["message_type"],
                idempotency_key=row["idempotency_key"],
                disposition=disposition,
            )

    return JSONResponse(
        status_code=202,
        content={
            "sequence_number": result_row["sequence_number"],
            "created_at": _isoformat(result_row["created_at"]),
            "disposition": disposition,
        },
        headers={"X-Request-Id": request_id},
    )


@router.get("/v1/messaging/inbox/{team_id}/{project_id}/{agent_id}")
async def get_inbox(
    request: Request,
    team_id: str = Path(..., max_length=_MAX_STABLE_ID_LEN),
    project_id: str = Path(..., max_length=_MAX_STABLE_ID_LEN),
    agent_id: str = Path(..., max_length=_MAX_STABLE_ID_LEN),
    since_sequence: int | None = Query(default=None, ge=0),
    limit: int | None = Query(default=None),
    principal: str = Depends(require_tenant_principal),
) -> JSONResponse:
    """Cursor-paginated read of one agent's inbox, ordered by sequence_number ASCENDING.

    `since_sequence` is the EXCLUSIVE lower bound (a plain integer — sequence_number is
    already a bare monotonic position, not sensitive, so no opaque-cursor encoding is
    needed here, unlike the identity/automation reads' base64 cursors). Tenant-scoped RLS
    means a tenant can only ever poll inboxes for agents within ITS OWN tenant — there is
    no separate cross-tenant check needed (RLS makes another tenant's rows structurally
    invisible, the same reasoning already used for automation's rule-id 404-not-403
    precedent).
    """
    request_id = _request_id()
    settings: MessagingSettings = request.app.state.messaging_settings
    if since_sequence is not None and not (_BIGINT_MIN <= since_sequence <= _BIGINT_MAX):
        return _error(422, "schema_invalid", "since_sequence is out of range", request_id)

    ceiling = settings.max_inbox_page_size
    if limit is None:
        limit_value = min(_DEFAULT_INBOX_LIMIT, ceiling)
    elif limit < _MIN_INBOX_LIMIT:
        limit_value = _MIN_INBOX_LIMIT
    elif limit > ceiling:
        limit_value = ceiling
    else:
        limit_value = limit

    async with get_tenant_session(principal) as session:
        rows, next_seq = await list_inbox_messages(
            session,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            since_sequence=since_sequence,
            limit=limit_value,
        )
    body = {
        "data": [_message_body(row) for row in rows],
        "next_since_sequence": next_seq,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


def _validate_state_body(
    body: dict[str, Any], settings: MessagingSettings
) -> tuple[str, str] | None:
    """Structural + bounds validation of a PUT /v1/state/{state_key} body.

    Returns (code, message) for a 422, or None when valid. Never touches the DB.
    """
    if set(body) - _ALLOWED_STATE_KEYS:
        return ("schema_invalid", "request contains unknown fields")
    if {"expected_version", "value"} - set(body):
        return ("schema_invalid", "request is missing required fields")

    expected_version = body.get("expected_version")
    if expected_version is not None and (
        isinstance(expected_version, bool)
        or not isinstance(expected_version, int)
        or expected_version < 1
    ):
        return ("schema_invalid", "expected_version must be null or a positive integer")

    value = body.get("value")
    if not isinstance(value, dict):
        return ("schema_invalid", "value must be a JSON object")
    try:
        serialized_size = len(json.dumps(value).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return ("schema_invalid", "value is not serializable")
    if serialized_size > settings.max_state_value_bytes:
        return (
            "state_value_too_large",
            f"value may be at most {settings.max_state_value_bytes} bytes serialized",
        )

    updated_by_agent_id = body.get("updated_by_agent_id")
    if updated_by_agent_id is not None and (
        not isinstance(updated_by_agent_id, str)
        or not updated_by_agent_id
        or len(updated_by_agent_id) > _MAX_UPDATED_BY_AGENT_ID_LEN
    ):
        return ("schema_invalid", "updated_by_agent_id must be a non-empty string")

    return None


@router.put("/v1/state/{state_key}")
async def write_state(
    state_key: str,
    request: Request,
    principal: str = Depends(require_tenant_principal),
) -> JSONResponse:
    """Compare-and-swap write of one shared-state key (optimistic concurrency, NOT
    distributed consensus).

    `expected_version: null` means create-only-if-absent (an existing key -> 409
    `already_exists`, echoing the CURRENT version). A non-null `expected_version` that
    does not match the row's current stored version -> 409 `version_conflict` (echoing the
    current version, or null if the key does not exist at all — there is no "current
    version" to echo for a key that was never created). A match increments `version` by
    exactly 1. Race-safe under concurrent writers to the SAME (tenant_id, state_key) via an
    atomic `UPDATE ... WHERE ... AND version = :expected` (see
    persistence.repositories.update_agent_state_cas).

    UNLIKE the message-send seam above, only a genuine 'created'/'updated' write is
    hash-chain audited — a version-conflict rejection changes nothing, so there is
    nothing tamper-evident to record (mirrors ADR-0011's automation_executions choice).
    """
    request_id = _request_id()
    settings: MessagingSettings = request.app.state.messaging_settings
    if len(state_key) > 256:
        return _error(422, "schema_invalid", "state_key is too long", request_id)

    body, error = await _parse_body(request, request_id)
    if error is not None:
        return error
    if body is None:
        # Unreachable: _parse_body's contract guarantees body is set when error is None.
        raise RuntimeError("_parse_body returned neither a body nor an error")

    structural = _validate_state_body(body, settings)
    if structural is not None:
        code, message = structural
        return _error(422, code, message, request_id)

    expected_version = body["expected_version"]
    value = body["value"]
    updated_by_agent_id = body.get("updated_by_agent_id")

    if expected_version is None:
        async with get_tenant_session(principal) as session:
            created = await create_agent_state_if_absent(
                session,
                tenant_id=principal,
                state_key=state_key,
                state_value=value,
                updated_by_agent_id=updated_by_agent_id,
            )
            if created is not None:
                await session.commit()
        if created is None:
            async with get_tenant_session(principal) as session:
                current = await get_agent_state(session, state_key)
            current_version = current["version"] if current is not None else None
            return JSONResponse(
                status_code=409,
                content={
                    "error": {
                        "code": "already_exists",
                        "message": "state_key already exists",
                        "request_id": request_id,
                    },
                    "current_version": current_version,
                },
                headers={"X-Request-Id": request_id},
            )
        result_row = created
        disposition = "created"
    else:
        async with get_tenant_session(principal) as session:
            updated = await update_agent_state_cas(
                session,
                state_key=state_key,
                expected_version=expected_version,
                state_value=value,
                updated_by_agent_id=updated_by_agent_id,
            )
            if updated is not None:
                await session.commit()
        if updated is None:
            async with get_tenant_session(principal) as session:
                current = await get_agent_state(session, state_key)
            current_version = current["version"] if current is not None else None
            return JSONResponse(
                status_code=409,
                content={
                    "error": {
                        "code": "version_conflict",
                        "message": "expected_version does not match the current stored version",
                        "request_id": request_id,
                    },
                    "current_version": current_version,
                },
                headers={"X-Request-Id": request_id},
            )
        result_row = updated
        disposition = "updated"

    async with get_privileged_session() as psession:
        async with psession.begin():
            await append_state_audit_link(
                psession,
                tenant_id=principal,
                state_key=state_key,
                version=result_row["version"],
                disposition=disposition,
                updated_by_agent_id=updated_by_agent_id,
            )

    return JSONResponse(
        status_code=200,
        content={
            "state_key": state_key,
            "version": result_row["version"],
            "updated_at": _isoformat(result_row["updated_at"]),
        },
        headers={"X-Request-Id": request_id},
    )


@router.get("/v1/state/{state_key}")
async def read_state(
    state_key: str, principal: str = Depends(require_tenant_principal)
) -> JSONResponse:
    request_id = _request_id()
    async with get_tenant_session(principal) as session:
        row = await get_agent_state(session, state_key)
    if row is None:
        return _error(404, "not_found", "state_key not found", request_id)
    return JSONResponse(
        status_code=200,
        content={
            "state_key": row["state_key"],
            "value": row["state_value"],
            "version": row["version"],
            "updated_at": _isoformat(row["updated_at"]),
        },
        headers={"X-Request-Id": request_id},
    )
