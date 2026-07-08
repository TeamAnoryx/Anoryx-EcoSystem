"""POST + GET /v1/identity/events — cross-product identity-event correlation (O-010, ADR-0010).

Lets Sentinel, Delta, and Rendly each push a NORMALIZED "who accessed what, where" record
(a principal took an action, at a tenant, optionally against a target) after their own
existing auth boundary fires — Sentinel's F-014 SSO login, Delta's admin-token use, Rendly's
JWT verification — into one durably audited, tenant-queryable log. This is a correlation
seam, NOT identity federation: each product keeps its own credential type and verification
logic; the Orchestrator never issues, verifies, or translates any of them (ADR-0010 honesty
boundary).

Gated by a per-source-product bearer (`ORCH_IDENTITY_SOURCE_TOKENS`) DISTINCT from every
other Orchestrator principal — source_product is resolved FROM the matched token, never
accepted from the request body (mirrors the ingest/relay seams' source_product discipline).
The read seam reuses the EXISTING O-006 per-tenant principal (`query_service_tokens` /
`require_tenant_principal`) — the SAME credential that already gates `/v1/events` — rather
than inventing a new tenant-read trust root.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from orchestrator.boundary import contains_nul
from orchestrator.config import IdentitySettings
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_identity_audit_link,
    insert_identity_event,
    list_identity_events,
)
from orchestrator.security import require_tenant_principal

router = APIRouter()

_BEARER_PREFIX = "Bearer "
_KNOWN_PRINCIPAL_TYPES = frozenset(
    {"operator", "tenant_user", "service_account", "peer_credential"}
)
_ALLOWED_INGEST_KEYS = frozenset(
    {
        "tenant_id",
        "principal_type",
        "principal_id",
        "action",
        "target",
        "idempotency_key",
        "occurred_at",
    }
)
_MAX_TENANT_ID_LEN = 64
_MAX_PRINCIPAL_ID_LEN = 256
_MAX_ACTION_LEN = 64
_MAX_TARGET_LEN = 256
_MAX_IDEMPOTENCY_KEY_LEN = 128

_DEFAULT_LIMIT = 50
_MIN_LIMIT = 1
_MAX_LIMIT = 200
_MAX_CURSOR_LENGTH = 512
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


def _resolve_source(request: Request, settings: IdentitySettings) -> str | None:
    """Constant-time-match the presented bearer against every configured identity source
    token. Returns the matched source_product, or None. Never accepted from the body."""
    header = request.headers.get("Authorization", "")
    if not header.startswith(_BEARER_PREFIX):
        return None
    presented = header[len(_BEARER_PREFIX) :]
    if not presented:
        return None
    matched: str | None = None
    for product, token in settings.source_tokens.items():
        if hmac.compare_digest(presented, token):
            matched = product
    return matched


def _clamp_limit(raw: int | None) -> int:
    if raw is None:
        return _DEFAULT_LIMIT
    if raw < _MIN_LIMIT:
        return _MIN_LIMIT
    if raw > _MAX_LIMIT:
        return _MAX_LIMIT
    return raw


def _encode_seq_cursor(sequence_number: int) -> str:
    return base64.urlsafe_b64encode(str(sequence_number).encode("utf-8")).decode("ascii")


def _decode_seq_cursor(cursor: str) -> int:
    """Decode a cursor -> sequence_number. Raises on malformed/out-of-BIGINT-range input
    (the call site maps every failure to a 422, never a DB DataError -> 503)."""
    value = int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    if not (_BIGINT_MIN <= value <= _BIGINT_MAX):
        raise ValueError("cursor sequence_number is outside the signed BIGINT range")
    return value


def _isoformat(value: object) -> object:
    return value.isoformat() if isinstance(value, datetime) else value


def _identity_event_body(row: dict[str, Any]) -> dict[str, Any]:
    body = {
        "tenant_id": row["tenant_id"],
        "source_product": row["source_product"],
        "principal_type": row["principal_type"],
        "principal_id": row["principal_id"],
        "action": row["action"],
        "idempotency_key": row["idempotency_key"],
        "occurred_at": _isoformat(row["occurred_at"]),
        "received_at": _isoformat(row["received_at"]),
    }
    if row.get("target") is not None:
        body["target"] = row["target"]
    return body


@router.post("/v1/identity/events")
async def ingest_identity_event(request: Request) -> JSONResponse:
    """Ingest one normalized identity/access event from Sentinel, Delta, or Rendly.

    Idempotent: a retried push with the same (source_product, idempotency_key) is recorded
    as `disposition: duplicate` (no second row), never an error. Every ingest ATTEMPT —
    fresh accept or duplicate — is hash-chain audited.
    """
    settings: IdentitySettings = request.app.state.identity_settings
    request_id = _request_id()

    source_product = _resolve_source(request, settings)
    if source_product is None:
        return _error(401, "unauthorized", "identity source authentication required", request_id)

    raw_body = await request.body()
    if len(raw_body) > settings.max_body_bytes:
        return _error(
            413, "request_too_large", "request body exceeds the maximum allowed size", request_id
        )
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(body, dict):
        return _error(422, "schema_invalid", "request body must be a JSON object", request_id)
    if set(body) - _ALLOWED_INGEST_KEYS:
        return _error(422, "schema_invalid", "request contains unknown fields", request_id)
    if contains_nul(body):
        return _error(
            422, "schema_invalid", "request contains a forbidden NUL character", request_id
        )

    tenant_id = body.get("tenant_id")
    principal_type = body.get("principal_type")
    principal_id = body.get("principal_id")
    action = body.get("action")
    target = body.get("target")
    idempotency_key = body.get("idempotency_key")
    occurred_at_raw = body.get("occurred_at")

    if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > _MAX_TENANT_ID_LEN:
        return _error(422, "schema_invalid", "tenant_id is required", request_id)
    if principal_type not in _KNOWN_PRINCIPAL_TYPES:
        return _error(
            422, "schema_invalid", "principal_type must be a known principal type", request_id
        )
    if (
        not isinstance(principal_id, str)
        or not principal_id
        or len(principal_id) > _MAX_PRINCIPAL_ID_LEN
    ):
        return _error(422, "schema_invalid", "principal_id is required", request_id)
    if not isinstance(action, str) or not action or len(action) > _MAX_ACTION_LEN:
        return _error(422, "schema_invalid", "action is required", request_id)
    if target is not None and (not isinstance(target, str) or len(target) > _MAX_TARGET_LEN):
        return _error(422, "schema_invalid", "target must be a string", request_id)
    if (
        not isinstance(idempotency_key, str)
        or not idempotency_key
        or len(idempotency_key) > _MAX_IDEMPOTENCY_KEY_LEN
    ):
        return _error(422, "schema_invalid", "idempotency_key is required", request_id)
    if not isinstance(occurred_at_raw, str):
        return _error(422, "schema_invalid", "occurred_at is required", request_id)
    try:
        occurred_at = datetime.fromisoformat(occurred_at_raw)
    except ValueError:
        return _error(
            422, "schema_invalid", "occurred_at must be an ISO-8601 timestamp", request_id
        )
    if occurred_at.tzinfo is None:
        return _error(
            422, "schema_invalid", "occurred_at must carry an explicit UTC offset", request_id
        )

    row = {
        "tenant_id": tenant_id,
        "source_product": source_product,
        "principal_type": principal_type,
        "principal_id": principal_id,
        "action": action,
        "target": target,
        "idempotency_key": idempotency_key,
        "occurred_at": occurred_at,
    }
    async with get_tenant_session(tenant_id) as session:
        inserted = await insert_identity_event(session, row)
        await session.commit()

    disposition = "accepted" if inserted else "duplicate"
    async with get_privileged_session() as psession:
        async with psession.begin():
            await append_identity_audit_link(
                psession,
                tenant_id=tenant_id,
                source_product=source_product,
                principal_type=principal_type,
                principal_id=principal_id,
                action=action,
                idempotency_key=idempotency_key,
                disposition=disposition,
                target=target,
            )

    return JSONResponse(
        status_code=202,
        content={"status": "accepted", "disposition": disposition},
        headers={"X-Request-Id": request_id},
    )


@router.get("/v1/identity/events")
async def query_identity_events(
    principal: str = Depends(require_tenant_principal),
    source_product: str | None = Query(default=None),
    principal_type: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=_MAX_CURSOR_LENGTH),
) -> JSONResponse:
    """Cursor-paginated read of this tenant's cross-product identity events.

    Reuses the O-006 per-tenant principal (query_service_tokens) — the read runs under
    get_tenant_session(principal), so RLS structurally scopes it to the caller's own tenant.
    """
    request_id = _request_id()
    limit_value = _clamp_limit(limit)
    decoded_cursor: int | None = None
    if cursor is not None:
        try:
            decoded_cursor = _decode_seq_cursor(cursor)
        except (ValueError, KeyError, TypeError, binascii.Error):
            return _error(422, "schema_invalid", "cursor is malformed", request_id)
    filters = {"source_product": source_product, "principal_type": principal_type, "action": action}
    async with get_tenant_session(principal) as session:
        rows, next_seq = await list_identity_events(
            session, filters=filters, limit=limit_value, cursor=decoded_cursor
        )
    body = {
        "data": [_identity_event_body(row) for row in rows],
        "next_cursor": _encode_seq_cursor(next_seq) if next_seq is not None else None,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})
