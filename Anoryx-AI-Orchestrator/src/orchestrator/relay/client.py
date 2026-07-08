"""Governed relay dispatch — relay_request (O-009, ADR-0009).

Centralises inter-app AI traffic (Delta/Rendly -> Sentinel) through the Orchestrator so it is
routed via a REGISTERED, ENABLED, HEALTHY Sentinel instance (the O-005 registry), re-validated
through the SSRF gate immediately before every outbound use (the same discipline the O-004/O-005
outbound calls already apply), and durably audited on a hash chain — whether the dispatch was
actually forwarded and answered, blocked before any outbound call, or failed at the transport
layer. Sentinel's OWN already-shipped gateway (F-004/F-005/F-006) is what monitors, redacts, and
routes the payload; this module's job is centralized, governed ROUTING + AUDIT, not
re-implementing Sentinel's detectors (ADR-0009 honesty boundary).

The CALLER (the router) validates target_path against the operator-configured allowlist and the
request shape before calling; this module trusts `target_path` is already allowlisted (mirrors
coordinator.py's "the CALLER validates... this module trusts" discipline).

SINGLE ATTEMPT, NO RETRY: unlike O-004/O-005's fire-and-forget bounded retries, a relay dispatch
is a synchronous call an interactive caller is waiting on, and automatically retrying a
non-idempotent LLM request risks duplicate side effects / duplicate provider cost. A relay
caller that wants a retry issues a new request (ADR-0009 honest deferral).

SECRET HYGIENE: sentinel_authorization (the tenant's own Sentinel virtual API key) and the
payload bytes are NEVER logged or persisted — the audit chain records only metadata (tenant_id,
source_product, sentinel_id, target_path, disposition, status_code, a sha256 content_hash, and a
short error_reason code).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from orchestrator.config import CoordinationSettings
from orchestrator.coordination.endpoint_validation import (
    EndpointValidationError,
    validate_endpoint_async,
)
from orchestrator.coordination.health import effective_health_status
from orchestrator.coordination.registry import fetch_sentinel
from orchestrator.persistence import repositories as repo
from orchestrator.persistence.database import get_privileged_session

logger = logging.getLogger(__name__)

_HTTP_OK_FLOOR = 200
_HTTP_OK_CEIL = 300


class RelayError(Exception):
    """A relay dispatch outcome that maps to a specific HTTP status.

    `status` is the HTTP status the router returns; `reason` is a short stable code (also
    the audit error_reason — never the payload or a secret).
    """

    def __init__(self, status: int, reason: str, message: str | None = None) -> None:
        self.status = status
        self.reason = reason
        super().__init__(message or reason)


class RelayTargetUnavailable(RelayError):
    """The target Sentinel is unknown, disabled, unhealthy, or fails SSRF re-validation.

    Maps to 503 — nothing was sent (a blocked disposition), never a partial/ambiguous send.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(503, reason)


class RelayUpstreamError(RelayError):
    """The outbound HTTP call to Sentinel failed at the transport layer (timeout/connect).

    Maps to 502 — a failed disposition; Sentinel may or may not have received the request.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(502, reason)


async def _audit(
    *,
    tenant_id: str,
    source_product: str,
    sentinel_id: str,
    target_path: str,
    disposition: str,
    status_code: int | None = None,
    content_hash: str | None = None,
    error_reason: str | None = None,
) -> None:
    """Append one relay_audit_log link in its own privileged transaction."""
    async with get_privileged_session() as psession:
        async with psession.begin():
            await repo.append_relay_audit_link(
                psession,
                tenant_id=tenant_id,
                source_product=source_product,
                sentinel_id=sentinel_id,
                target_path=target_path,
                disposition=disposition,
                status_code=status_code,
                content_hash=content_hash,
                error_reason=error_reason,
            )


async def relay_request(
    *,
    sentinel_id: str,
    target_path: str,
    tenant_id: str,
    source_product: str,
    body_bytes: bytes,
    sentinel_authorization: str,
    settings: CoordinationSettings,
) -> tuple[int, bytes, str]:
    """Dispatch one request to a registered Sentinel. Returns (status_code, body, content_type).

    Raises RelayTargetUnavailable (503) if the target is unknown, disabled, unhealthy, or its
    endpoint no longer validates (SSRF) — nothing is sent in that case. Raises
    RelayUpstreamError (502) on a transport-layer failure. Every terminal outcome — forwarded
    (any status Sentinel returned), blocked, or failed — is durably audited before returning
    or raising. The request body is forwarded byte-identical (never re-serialized) so nothing
    the Orchestrator does can alter what Sentinel's own hooks inspect.
    """
    import httpx

    content_hash = hashlib.sha256(body_bytes).hexdigest()

    sentinel = await fetch_sentinel(sentinel_id)
    if sentinel is None or not sentinel.get("enabled", True):
        reason = "unknown_target" if sentinel is None else "target_disabled"
        await _audit(
            tenant_id=tenant_id,
            source_product=source_product,
            sentinel_id=sentinel_id,
            target_path=target_path,
            disposition="blocked",
            content_hash=content_hash,
            error_reason=reason,
        )
        raise RelayTargetUnavailable(reason)

    health = effective_health_status(
        sentinel, staleness_seconds=settings.staleness_seconds, now=datetime.now(timezone.utc)
    )
    if health != "healthy":
        await _audit(
            tenant_id=tenant_id,
            source_product=source_product,
            sentinel_id=sentinel_id,
            target_path=target_path,
            disposition="blocked",
            content_hash=content_hash,
            error_reason=f"target_{health}",
        )
        raise RelayTargetUnavailable(f"target_{health}")

    try:
        validated_endpoint = await validate_endpoint_async(
            sentinel["endpoint"],
            allowlist=settings.endpoint_allowlist,
            allow_http=settings.allow_http,
        )
    except EndpointValidationError as exc:
        await _audit(
            tenant_id=tenant_id,
            source_product=source_product,
            sentinel_id=sentinel_id,
            target_path=target_path,
            disposition="blocked",
            content_hash=content_hash,
            error_reason=f"invalid_endpoint:{exc.reason}",
        )
        raise RelayTargetUnavailable(f"invalid_endpoint:{exc.reason}") from exc

    url = validated_endpoint.rstrip("/") + target_path
    headers = {
        "Authorization": f"Bearer {sentinel_authorization}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=settings.relay.http_timeout_seconds) as client:
            resp = await client.post(url, content=body_bytes, headers=headers)
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        await _audit(
            tenant_id=tenant_id,
            source_product=source_product,
            sentinel_id=sentinel_id,
            target_path=target_path,
            disposition="failed",
            content_hash=content_hash,
            error_reason="connect_error",
        )
        raise RelayUpstreamError("connect_error") from exc

    # Any response Sentinel actually returns — 2xx or not — is a successful RELAY: the
    # Orchestrator reached Sentinel and got an answer back. A non-2xx is SENTINEL's own
    # decision (e.g. its F-005 hooks blocked the content, or its own auth rejected the
    # virtual key) — never miscast as a relay failure. Only a target we never reached is
    # blocked/failed.
    is_ok = _HTTP_OK_FLOOR <= resp.status_code < _HTTP_OK_CEIL
    if not is_ok:
        logger.info(
            "relay dispatch forwarded; Sentinel returned a non-2xx",
            extra={"sentinel_id": sentinel_id, "status_code": resp.status_code},
        )
    await _audit(
        tenant_id=tenant_id,
        source_product=source_product,
        sentinel_id=sentinel_id,
        target_path=target_path,
        disposition="forwarded",
        status_code=resp.status_code,
        content_hash=content_hash,
    )
    return resp.status_code, resp.content, resp.headers.get("content-type", "application/json")
