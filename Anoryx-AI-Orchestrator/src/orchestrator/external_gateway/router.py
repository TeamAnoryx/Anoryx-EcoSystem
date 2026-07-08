"""POST/GET/POST /v1/admin/external-keys[...] + GET /v1/external/events (O-013, ADR-0013).

Two independent seams sharing one new trust boundary — the third-party API key:

A. Key management (`/v1/admin/external-keys`) — gated by the SAME operator bearer
   (`ORCH_ADMIN_TOKEN`, `CoordinationSettings.admin_token`) that already fronts the O-005
   registry seams and the O-007 admin API (byte-identical `_require_admin` policy,
   mirrored locally per this codebase's established per-router convention — see
   `admin/router.py`'s own docstring on why each router carries its own copy rather than
   importing another module's private helper). An operator issues a key scoped to exactly
   one tenant, a rate limit, and an explicit capability allow-list (`scopes`). The
   plaintext key is returned exactly once, at issuance, and never stored or logged again.

B. The gated read (`GET /v1/external/events`) — a third-party-facing, rate-limited,
   scope-checked, uniformly-audited mirror of the O-006 `GET /v1/events` seam (same
   EventMetadata projection, same cursor pagination), gated by `require_third_party_api_key`
   instead of `require_tenant_principal`. Disabled by default
   (`ExternalGatewaySettings.enabled`, ORCH_EXTERNAL_GATEWAY_ENABLED) — an unconfigured
   deployment never exposes a third-party-facing surface merely by upgrading.

Every request for which a key resolves to a tenant is chain-audited to
`external_gateway_audit_log`, regardless of outcome (allowed / scope_denied /
rate_limited / revoked) — the whole point of a governance gateway is a durable record of
what was tried, not only what succeeded (ADR-0013). A wholly unknown/malformed key never
resolves a tenant and is therefore never audited here (mirrors `require_tenant_principal`'s
identical non-audited-401 precedent).

NOT the roadmap's literal "global API gateway for all third-party interactions with the
ecosystem" — this gates ONE Orchestrator read seam, not a cross-product proxy, and it does
not integrate with F-026 (the MCP layer), which does not exist yet. See ADR-0013's honesty
boundaries for the full disclosure.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from orchestrator.boundary import contains_nul
from orchestrator.config import CoordinationSettings, ExternalGatewaySettings
from orchestrator.external_gateway.auth import (
    ExternalGatewayPrincipal,
    require_third_party_api_key,
)
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_external_gateway_audit_link,
    count_third_party_api_keys,
    increment_external_gateway_rate_limit,
    insert_third_party_api_key,
    list_events,
    list_third_party_api_keys,
    lock_external_gateway_key_cap,
    revoke_third_party_api_key,
)
from orchestrator.query.router import (
    _clamp_limit,
    _decode_seq_cursor,
    _encode_seq_cursor,
    _event_metadata_body,
)

router = APIRouter()

_BEARER_PREFIX = "Bearer "
_KEY_HEADER_SECRET_PREFIX = "eak_"  # noqa: S105 - a public prefix, not a secret value
_KEY_ID_PREFIX = "extkey-"

# The only capability this gateway gates in v1 — a closed, explicit enum (not an open
# free-text field) so an issuance request cannot grant a scope the router does not
# actually enforce anywhere. Extending this list requires wiring a matching route below.
_KNOWN_SCOPES = frozenset({"events:read"})
_ROUTE_EVENTS_READ = "GET /v1/external/events"
_SCOPE_FOR_ROUTE = {_ROUTE_EVENTS_READ: "events:read"}

_MAX_TENANT_ID_LEN = 64
_MAX_LABEL_LEN = 128
_MAX_CURSOR_LENGTH = 512
_ALLOWED_ISSUE_KEYS = frozenset({"tenant_id", "label", "scopes", "rate_limit_per_minute"})


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


def _require_admin(
    request: Request, settings: CoordinationSettings, request_id: str
) -> JSONResponse | None:
    """Fail-closed operator-token gate. Returns an error JSONResponse, or None on success.

    Byte-identical policy to `admin.router._require_admin` / `coordination.router.
    _require_admin` (same operator principal): missing / non-"Bearer " / empty
    Authorization -> 401; no admin token configured -> 401 (fail-closed, never matches);
    a present token that mismatches -> 403. Constant-time compare via `hmac.compare_digest`.
    """
    header = request.headers.get("Authorization", "")
    if not header.startswith(_BEARER_PREFIX):
        return _error(401, "unauthorized", "operator authentication required", request_id)
    presented = header[len(_BEARER_PREFIX) :]
    if not presented:
        return _error(401, "unauthorized", "operator authentication required", request_id)
    if settings.admin_token is None:
        return _error(401, "unauthorized", "operator authentication required", request_id)
    if not hmac.compare_digest(presented, settings.admin_token):
        return _error(403, "forbidden", "operator is not authorized", request_id)
    return None


async def _parse_body(
    request: Request, request_id: str
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Parse + NUL-check the raw request body (mirrors messaging/router.py verbatim)."""
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


def _key_metadata_body(row: dict[str, Any]) -> dict[str, Any]:
    """Project one third_party_api_keys row for an admin response (NEVER key_hash)."""
    return {
        "key_id": row["key_id"],
        "tenant_id": row["tenant_id"],
        "label": row["label"],
        "scopes": list(row["scopes"]),
        "status": row["status"],
        "rate_limit_per_minute": row["rate_limit_per_minute"],
        "created_at": _isoformat(row["created_at"]),
        "revoked_at": _isoformat(row["revoked_at"]),
    }


def _validate_issue_body(
    body: dict[str, Any], settings: ExternalGatewaySettings
) -> tuple[str, str] | None:
    """Structural + bounds validation of a POST /v1/admin/external-keys body.

    Returns (code, message) for a 422, or None when valid. Never touches the DB.
    """
    if set(body) - _ALLOWED_ISSUE_KEYS:
        return ("schema_invalid", "request contains unknown fields")
    if {"tenant_id", "label", "scopes"} - set(body):
        return ("schema_invalid", "request is missing required fields")

    tenant_id = body.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > _MAX_TENANT_ID_LEN:
        return ("schema_invalid", "tenant_id is required")

    label = body.get("label")
    if not isinstance(label, str) or not label or len(label) > _MAX_LABEL_LEN:
        return ("schema_invalid", "label is required")

    scopes = body.get("scopes")
    if not isinstance(scopes, list) or not scopes or not all(isinstance(s, str) for s in scopes):
        return ("schema_invalid", "scopes must be a non-empty array of strings")
    if not set(scopes) <= _KNOWN_SCOPES:
        return ("schema_invalid", f"scopes must be a subset of {sorted(_KNOWN_SCOPES)}")

    rate_limit_per_minute = body.get("rate_limit_per_minute")
    if rate_limit_per_minute is not None and (
        isinstance(rate_limit_per_minute, bool)
        or not isinstance(rate_limit_per_minute, int)
        or not (1 <= rate_limit_per_minute <= settings.max_rate_limit_per_minute)
    ):
        return (
            "schema_invalid",
            f"rate_limit_per_minute must be an integer between 1 and "
            f"{settings.max_rate_limit_per_minute}",
        )

    return None


@router.post("/v1/admin/external-keys")
async def issue_external_key(request: Request) -> JSONResponse:
    """Issue one third-party API key for a tenant (operator-gated).

    The plaintext key (`eak_...`) is returned in THIS response only — it is never
    stored or logged; only its SHA-256 hash persists. Enforces
    `ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT` at issuance time (422
    `key_limit_exceeded`, never a 5xx) via a tenant-keyed advisory lock + COUNT in the
    SAME transaction as the INSERT (TOCTOU-safe, mirrors `lock_messaging_message_cap`).
    """
    request_id = _request_id()
    coordination_settings: CoordinationSettings = request.app.state.coordination_settings
    auth_error = _require_admin(request, coordination_settings, request_id)
    if auth_error is not None:
        return auth_error

    gateway_settings: ExternalGatewaySettings = request.app.state.external_gateway_settings

    body, error = await _parse_body(request, request_id)
    if error is not None:
        return error
    if body is None:
        raise RuntimeError("_parse_body returned neither a body nor an error")

    structural = _validate_issue_body(body, gateway_settings)
    if structural is not None:
        code, message = structural
        return _error(422, code, message, request_id)

    tenant_id = body["tenant_id"]
    plaintext_key = _KEY_HEADER_SECRET_PREFIX + secrets.token_urlsafe(32)
    row = {
        "key_id": _KEY_ID_PREFIX + uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "key_hash": hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest(),
        "label": body["label"],
        "scopes": sorted(set(body["scopes"])),
        "status": "active",
        "rate_limit_per_minute": (
            body.get("rate_limit_per_minute") or gateway_settings.default_rate_limit_per_minute
        ),
    }

    async with get_privileged_session() as session:
        async with session.begin():
            await lock_external_gateway_key_cap(session, tenant_id)
            existing_count = await count_third_party_api_keys(session, tenant_id)
            if existing_count >= gateway_settings.max_keys_per_tenant:
                return _error(
                    422,
                    "key_limit_exceeded",
                    f"this tenant has reached its external-key limit of "
                    f"{gateway_settings.max_keys_per_tenant}",
                    request_id,
                )
            inserted = await insert_third_party_api_key(session, row)

    content = _key_metadata_body(inserted)
    content["api_key"] = plaintext_key
    return JSONResponse(status_code=201, content=content, headers={"X-Request-Id": request_id})


@router.get("/v1/admin/external-keys")
async def list_external_keys(
    request: Request, tenant_id: str | None = Query(default=None)
) -> JSONResponse:
    """List third-party API key metadata (operator-gated, optionally filtered by tenant).

    Never projects `key_hash` — the plaintext secret was shown exactly once, at issuance.
    """
    request_id = _request_id()
    settings: CoordinationSettings = request.app.state.coordination_settings
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    async with get_privileged_session() as session:
        rows = await list_third_party_api_keys(session, tenant_id=tenant_id)
    body = {"data": [_key_metadata_body(row) for row in rows]}
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


@router.post("/v1/admin/external-keys/{key_id}/revoke")
async def revoke_external_key(request: Request, key_id: str) -> JSONResponse:
    """Revoke one third-party API key (operator-gated). Idempotent — revoking an
    already-revoked key re-returns its current (still-revoked) state, never an error.
    404 if key_id is unknown.
    """
    request_id = _request_id()
    settings: CoordinationSettings = request.app.state.coordination_settings
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    async with get_privileged_session() as session:
        async with session.begin():
            updated = await revoke_third_party_api_key(session, key_id)
    if updated is None:
        return _error(404, "not_found", "external key not found", request_id)
    return JSONResponse(
        status_code=200, content=_key_metadata_body(updated), headers={"X-Request-Id": request_id}
    )


async def _audit(principal: ExternalGatewayPrincipal, route: str, outcome: str) -> None:
    """Append one hash-chained external_gateway_audit_log link (privileged session)."""
    async with get_privileged_session() as session:
        async with session.begin():
            await append_external_gateway_audit_link(
                session,
                tenant_id=principal.tenant_id,
                key_id=principal.key_id,
                route=route,
                outcome=outcome,
            )


@router.get("/v1/external/events")
async def external_query_events(
    request: Request,
    principal: ExternalGatewayPrincipal = Depends(  # noqa: B008 - standard FastAPI DI pattern
        require_third_party_api_key
    ),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=_MAX_CURSOR_LENGTH),
) -> JSONResponse:
    """Third-party-facing, rate-limited, scope-checked mirror of `GET /v1/events`
    (ADR-0013).

    404s outright when `ORCH_EXTERNAL_GATEWAY_ENABLED` is off (the honest "this surface
    does not exist yet" response — checked BEFORE resolving the key further, so a
    disabled deployment leaks no information about key validity). A revoked key or one
    missing the `events:read` scope is a chain-audited 403; exceeding the key's
    `rate_limit_per_minute` is a chain-audited 429. Every other outcome (a genuine read)
    is a chain-audited 'allowed'. The projection is EventMetadata only (never `payload`),
    identical to the O-006 seam this mirrors.
    """
    request_id = _request_id()
    gateway_settings: ExternalGatewaySettings = request.app.state.external_gateway_settings
    if not gateway_settings.enabled:
        return _error(404, "not_found", "the external gateway is not enabled", request_id)

    route = _ROUTE_EVENTS_READ
    required_scope = _SCOPE_FOR_ROUTE[route]

    if principal.status != "active":
        await _audit(principal, route, "revoked")
        return _error(403, "forbidden", "this API key has been revoked", request_id)

    if required_scope not in principal.scopes:
        await _audit(principal, route, "scope_denied")
        return _error(403, "forbidden", "this API key is not scoped for this route", request_id)

    limit_value = _clamp_limit(limit)
    decoded_cursor: int | None = None
    if cursor is not None:
        try:
            decoded_cursor = _decode_seq_cursor(cursor)
        except (ValueError, KeyError, TypeError, binascii.Error):
            return _error(422, "schema_invalid", "cursor is malformed", request_id)

    window_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    async with get_privileged_session() as session:
        async with session.begin():
            request_count = await increment_external_gateway_rate_limit(
                session, key_id=principal.key_id, window_start=window_start
            )
    if request_count > principal.rate_limit_per_minute:
        await _audit(principal, route, "rate_limited")
        return _error(429, "rate_limited", "this API key has exceeded its rate limit", request_id)

    await _audit(principal, route, "allowed")

    async with get_tenant_session(principal.tenant_id) as session:
        rows, next_seq = await list_events(
            session, filters={}, limit=limit_value, cursor=decoded_cursor
        )
    body = {
        "data": [_event_metadata_body(row) for row in rows],
        "next_cursor": _encode_seq_cursor(next_seq) if next_seq is not None else None,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})
