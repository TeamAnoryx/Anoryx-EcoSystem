"""POST /v1/relay/dispatch — governed Sentinel relay for inter-app AI traffic (O-009, ADR-0009).

Lets Delta/Rendly route their Sentinel-bound AI traffic THROUGH the Orchestrator instead of
calling a Sentinel instance directly, so it is centrally registry-gated, SSRF-validated, and
hash-chain audited (relay.client.relay_request). Sentinel's own already-shipped gateway
(F-004/F-005/F-006) is what actually monitors/redacts/routes the payload once it arrives —
this seam is centralized, governed dispatch, not a re-implementation of Sentinel's detectors.

Gated by a per-source-product bearer (`ORCH_RELAY_SOURCE_TOKENS`) DISTINCT from every other
Orchestrator principal (ORCH_ADMIN_TOKEN operator, ORCH_INGEST_HMAC_SECRET Sentinel peer,
SENTINEL_ADMIN_TOKEN outbound) — source_product is resolved FROM the matched token, never
accepted from the request body (mirrors the ingest seam's source_product discipline). The
TENANT'S OWN Sentinel virtual API key travels in a separate `X-Sentinel-Authorization` header
and is forwarded to Sentinel unchanged; the Orchestrator never stores or mints it.
"""

from __future__ import annotations

import hmac
import json
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from orchestrator.boundary import contains_nul
from orchestrator.config import CoordinationSettings
from orchestrator.relay.client import RelayError, relay_request

router = APIRouter()

_BEARER_PREFIX = "Bearer "
_SENTINEL_AUTH_HEADER = "X-Sentinel-Authorization"  # noqa: S105 - header name, not a secret
_ALLOWED_KEYS = frozenset({"tenant_id", "sentinel_id", "target_path", "payload"})


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _resolve_source(request: Request, settings: CoordinationSettings) -> str | None:
    """Constant-time-match the presented bearer against every configured relay source token.

    Returns the matched source_product, or None (unauthenticated / unrecognized token).
    source_product is ALWAYS server-resolved from the token — never accepted from the body.
    """
    header = request.headers.get("Authorization", "")
    if not header.startswith(_BEARER_PREFIX):
        return None
    presented = header[len(_BEARER_PREFIX) :]
    if not presented:
        return None
    matched: str | None = None
    for product, token in settings.relay.source_tokens.items():
        if hmac.compare_digest(presented, token):
            matched = product
    return matched


@router.post("/v1/relay/dispatch")
async def dispatch(request: Request) -> Response:
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()

    source_product = _resolve_source(request, settings)
    if source_product is None:
        return _error(401, "unauthorized", "relay source authentication required", request_id)

    sentinel_auth = request.headers.get(_SENTINEL_AUTH_HEADER, "")
    if not sentinel_auth:
        return _error(
            401,
            "unauthorized",
            f"{_SENTINEL_AUTH_HEADER} (the tenant's Sentinel virtual API key) is required",
            request_id,
        )

    raw_body = await request.body()
    if len(raw_body) > settings.relay.max_body_bytes:
        return _error(
            413, "request_too_large", "request body exceeds the maximum allowed size", request_id
        )
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(body, dict):
        return _error(422, "schema_invalid", "request body must be a JSON object", request_id)
    if set(body) - _ALLOWED_KEYS:
        return _error(422, "schema_invalid", "request contains unknown fields", request_id)
    if contains_nul(body):
        return _error(
            422, "schema_invalid", "request contains a forbidden NUL character", request_id
        )

    tenant_id = body.get("tenant_id")
    sentinel_id = body.get("sentinel_id")
    target_path = body.get("target_path")
    payload = body.get("payload")
    if not isinstance(tenant_id, str) or not tenant_id:
        return _error(422, "schema_invalid", "tenant_id is required", request_id)
    if not isinstance(sentinel_id, str) or not sentinel_id:
        return _error(422, "schema_invalid", "sentinel_id is required", request_id)
    if not isinstance(target_path, str) or target_path not in settings.relay.allowed_paths:
        return _error(
            422, "path_not_allowed", "target_path is not a relay-eligible Sentinel path", request_id
        )
    if not isinstance(payload, dict):
        return _error(
            422, "schema_invalid", "payload is required and must be an object", request_id
        )
    if payload.get("stream") is True:
        return _error(
            422,
            "streaming_not_supported",
            "streaming relay is not supported in this release",
            request_id,
        )

    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    try:
        status_code, resp_body, content_type = await relay_request(
            sentinel_id=sentinel_id,
            target_path=target_path,
            tenant_id=tenant_id,
            source_product=source_product,
            body_bytes=payload_bytes,
            sentinel_authorization=sentinel_auth,
            settings=settings,
        )
    except RelayError as exc:
        return _error(exc.status, exc.reason, str(exc), request_id)

    return Response(
        content=resp_body,
        status_code=status_code,
        media_type=content_type,
        headers={"X-Request-Id": request_id},
    )
