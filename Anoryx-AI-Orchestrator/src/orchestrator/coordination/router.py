"""Registry CRUD + coordinated-push seams (O-005, ADR-0005), gated by ORCH_ADMIN_TOKEN.

Mirrors the O-004 distribution router's boundary discipline (fail-closed bearer, parse +
structural validation, NUL guard, then delegate), but the registry is OPERATOR infra: it is
gated by a NEW dedicated operator token (ORCH_ADMIN_TOKEN), distinct from the peer
ORCH_SERVICE_TOKEN — operator fleet-management is not a peer-ingest seam. Endpoint validation
(SSRF) happens inside the registry layer; this router maps its typed errors to HTTP. Any error
below the auth boundary propagates to the app fail-safe handler (503).

Routes (all operator-gated):
  POST   /v1/registry/sentinels          register a Sentinel instance
  GET    /v1/registry/sentinels          list registered Sentinels
  GET    /v1/registry/sentinels/{id}     read one
  PATCH  /v1/registry/sentinels/{id}     modify (endpoint/capabilities/peer_auth_ref/enabled)
  DELETE /v1/registry/sentinels/{id}     deregister
  POST   /v1/registry/health-check       run a health cycle, return per-sentinel transitions
  POST   /v1/policies/coordinate         fan a policy across healthy + capable targets
"""

from __future__ import annotations

import hmac
import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from orchestrator.boundary import contains_nul
from orchestrator.config import CoordinationSettings
from orchestrator.coordination import registry
from orchestrator.coordination.coordinator import coordinate_push
from orchestrator.coordination.endpoint_validation import EndpointValidationError
from orchestrator.coordination.health import run_health_cycle
from orchestrator.coordination.registry import (
    RegistryValidationError,
    SentinelConflictError,
    SentinelNotFoundError,
)
from orchestrator.schema_validation import policy_schema_errors

router = APIRouter()

_BEARER_PREFIX = "Bearer "
# Fail-safe cap on the operator request body (generous for any legitimate registry op) so a
# huge payload cannot be buffered + parsed before the NUL/schema guards fire.
_MAX_BODY_BYTES = 65536
_ALLOWED_REGISTER_KEYS = frozenset({"sentinel_id", "endpoint", "capabilities", "peer_auth_ref"})
_ALLOWED_MODIFY_KEYS = frozenset({"endpoint", "capabilities", "peer_auth_ref", "enabled"})
_ALLOWED_COORDINATE_KEYS = frozenset({"policy"})


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _require_admin(
    request: Request, settings: CoordinationSettings, request_id: str
) -> JSONResponse | None:
    """Fail-closed operator-token gate. Returns an error JSONResponse, or None on success.

    Missing / non-"Bearer " / empty Authorization → 401. If no admin token is configured the
    seam can NEVER match → 401 (fail-closed). A present token that mismatches → 403.
    Constant-time compare.
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


def _isoformat(value: object) -> object:
    return value.isoformat() if isinstance(value, datetime) else value


def _serialize_sentinel(row: dict[str, Any]) -> dict[str, Any]:
    """Serialize a registry row for a response. peer_auth_ref is a non-secret label (safe)."""
    return {
        "sentinel_id": row["sentinel_id"],
        "endpoint": row["endpoint"],
        "peer_auth_ref": row["peer_auth_ref"],
        "capabilities": row["capabilities"],
        "health_status": row["health_status"],
        "consecutive_failures": row["consecutive_failures"],
        "last_checked_at": _isoformat(row.get("last_checked_at")),
        "last_healthy_at": _isoformat(row.get("last_healthy_at")),
        "enabled": row["enabled"],
        "created_at": _isoformat(row.get("created_at")),
        "updated_at": _isoformat(row.get("updated_at")),
    }


async def _parse_object_body(
    request: Request, request_id: str
) -> tuple[dict | None, JSONResponse | None]:
    """Parse a size-capped, NUL-guarded JSON-object body. Returns (body, None) or (None, error)."""
    raw_body = await request.body()
    if len(raw_body) > _MAX_BODY_BYTES:
        return None, _error(
            413, "request_too_large", "request body exceeds the maximum allowed size", request_id
        )
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(body, dict):
        return None, _error(422, "schema_invalid", "request body must be a JSON object", request_id)
    if contains_nul(body):
        return None, _error(
            422, "schema_invalid", "request contains a forbidden NUL character", request_id
        )
    return body, None


def _map_registry_error(exc: Exception, request_id: str) -> JSONResponse:
    """Map a registry/endpoint typed error to its HTTP response."""
    if isinstance(exc, (RegistryValidationError, EndpointValidationError)):
        return _error(422, exc.reason, str(exc), request_id)
    if isinstance(exc, SentinelConflictError):
        return _error(409, "already_registered", str(exc), request_id)
    if isinstance(exc, SentinelNotFoundError):
        return _error(404, "not_found", str(exc), request_id)
    raise exc  # unexpected → app fail-safe handler (503)


@router.post("/v1/registry/sentinels")
async def register(request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    body, parse_error = await _parse_object_body(request, request_id)
    if parse_error is not None:
        return parse_error
    if set(body) - _ALLOWED_REGISTER_KEYS:
        return _error(422, "schema_invalid", "request contains unknown fields", request_id)
    try:
        created = await registry.register_sentinel(
            sentinel_id=body.get("sentinel_id"),
            endpoint=body.get("endpoint"),
            capabilities=body.get("capabilities"),
            peer_auth_ref=body.get("peer_auth_ref"),
            settings=settings,
        )
    except (RegistryValidationError, EndpointValidationError, SentinelConflictError) as exc:
        return _map_registry_error(exc, request_id)
    return JSONResponse(
        status_code=201, content=_serialize_sentinel(created), headers={"X-Request-Id": request_id}
    )


@router.get("/v1/registry/sentinels")
async def list_registered(request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    rows = await registry.fetch_sentinels()
    return JSONResponse(
        status_code=200,
        content={"sentinels": [_serialize_sentinel(r) for r in rows]},
        headers={"X-Request-Id": request_id},
    )


@router.get("/v1/registry/sentinels/{sentinel_id}")
async def read_one(sentinel_id: str, request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    row = await registry.fetch_sentinel(sentinel_id)
    if row is None:
        return _error(404, "not_found", "sentinel not found", request_id)
    return JSONResponse(
        status_code=200, content=_serialize_sentinel(row), headers={"X-Request-Id": request_id}
    )


@router.patch("/v1/registry/sentinels/{sentinel_id}")
async def modify(sentinel_id: str, request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    body, parse_error = await _parse_object_body(request, request_id)
    if parse_error is not None:
        return parse_error
    if set(body) - _ALLOWED_MODIFY_KEYS:
        return _error(422, "schema_invalid", "request contains unknown fields", request_id)
    try:
        updated = await registry.modify_sentinel(
            sentinel_id,
            endpoint=body.get("endpoint"),
            capabilities=body.get("capabilities"),
            peer_auth_ref=body.get("peer_auth_ref"),
            enabled=body.get("enabled"),
            settings=settings,
        )
    except (RegistryValidationError, EndpointValidationError, SentinelNotFoundError) as exc:
        return _map_registry_error(exc, request_id)
    return JSONResponse(
        status_code=200, content=_serialize_sentinel(updated), headers={"X-Request-Id": request_id}
    )


@router.delete("/v1/registry/sentinels/{sentinel_id}")
async def deregister(sentinel_id: str, request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    try:
        await registry.deregister_sentinel(sentinel_id)
    except SentinelNotFoundError as exc:
        return _map_registry_error(exc, request_id)
    return JSONResponse(
        status_code=200,
        content={"sentinel_id": sentinel_id, "deregistered": True},
        headers={"X-Request-Id": request_id},
    )


@router.post("/v1/registry/health-check")
async def health_check(request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    results = await run_health_cycle(settings=settings)
    return JSONResponse(
        status_code=200, content={"results": results}, headers={"X-Request-Id": request_id}
    )


@router.post("/v1/policies/coordinate")
async def coordinate(request: Request) -> JSONResponse:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    body, parse_error = await _parse_object_body(request, request_id)
    if parse_error is not None:
        return parse_error
    if set(body) - _ALLOWED_COORDINATE_KEYS:
        return _error(422, "schema_invalid", "request contains unknown fields", request_id)
    policy = body.get("policy")
    if not isinstance(policy, dict):
        return _error(422, "schema_invalid", "policy is required and must be an object", request_id)
    # Locked-schema policy validation (structural guard; Sentinel intake is the verifying
    # authority — the Orchestrator never re-verifies the JWS, ADR-0004).
    if policy_schema_errors(policy):
        return _error(422, "policy_schema_invalid", "policy failed schema validation", request_id)
    # Server-resolved identity — the locked schema guarantees these are present; tenant_id is
    # NEVER a client header.
    tenant_id = policy["tenant_id"]
    result = await coordinate_push(policy, tenant_id, settings=settings)
    return JSONResponse(status_code=202, content=result, headers={"X-Request-Id": request_id})
