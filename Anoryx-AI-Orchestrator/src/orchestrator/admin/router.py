"""GET /v1/admin/events/recent + /v1/admin/distributions/recent + /v1/admin/identity/events/recent
— the O-007 admin API (ADR-0007) plus the O-010 identity-correlation admin read (ADR-0010),
plus GET /v1/admin/dashboard/summary (O-014, ADR-0014, a bounded aggregation over data these
existing reads already expose), plus GET /admin serving the minimal static operator UI.

Gated by the SAME operator bearer (`ORCH_ADMIN_TOKEN`, `CoordinationSettings.admin_token`)
that already fronts the O-005 registry seams — the admin API is the same operator
principal, not a new trust root. Mirrors the registry router's boundary discipline
(fail-closed constant-time bearer compare; ADR-0005), but both reads run on the
PRIVILEGED session and are deliberately CROSS-TENANT (fleet triage), never tenant-scoped —
that is the documented honesty boundary (ADR-0007), not an oversight. Both reads are
metadata-only: never `payload` (events), never `signed_record` / `content_hash`
(distributions).

The static UI (`GET /admin`) is a single dependency-free HTML/JS page, NOT the Next.js
console the Anoryx-Sentinel frontend convention uses (ADR-0007 honesty boundary — the
Orchestrator has no existing frontend build toolchain, and standing one up for a "minimal"
read-only fleet view is out of scope here). The page itself carries no secret; the operator
pastes the bearer token client-side and it is only ever attached as an Authorization header
to the two admin JSON endpoints below.
"""

from __future__ import annotations

import hmac
import os
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from orchestrator.config import CoordinationSettings
from orchestrator.coordination.registry import AUTO_ROLLBACK_REASON_PREFIX
from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import (
    count_sentinels_by_enabled,
    count_sentinels_by_health_status,
    list_recent_distributions_admin,
    list_recent_events_admin,
    list_recent_identity_events_admin,
    list_recent_registry_audit_admin,
)

router = APIRouter()

_BEARER_PREFIX = "Bearer "

_DEFAULT_LIMIT = 50
_MIN_LIMIT = 1
_MAX_LIMIT = 200

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


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

    Byte-identical policy to `coordination.router._require_admin` (same operator
    principal): missing / non-"Bearer " / empty Authorization -> 401; no admin token
    configured -> 401 (fail-closed, never matches); a present token that mismatches -> 403.
    Constant-time compare via `hmac.compare_digest`.
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


def _clamp_limit(raw: int | None) -> int:
    """Clamp a requested limit into [1, 200], defaulting to 50 when absent."""
    if raw is None:
        return _DEFAULT_LIMIT
    if raw < _MIN_LIMIT:
        return _MIN_LIMIT
    if raw > _MAX_LIMIT:
        return _MAX_LIMIT
    return raw


def _isoformat(value: object) -> object:
    return value.isoformat() if isinstance(value, datetime) else value


def _distribution_summary_body(row: dict[str, Any]) -> dict[str, Any]:
    """Project one policy_distributions row to AdminDistributionSummary.

    Allow-list only — NEVER `signed_record` / `content_hash` (no policy body on a
    fleet-overview read); the repo layer already excludes them, this is a defense-in-depth
    re-assertion at the response boundary.
    """
    return {
        "distribution_id": row["distribution_id"],
        "policy_id": row["policy_id"],
        "tenant_id": row["tenant_id"],
        "policy_type": row["policy_type"],
        "state": row["state"],
        "created_at": _isoformat(row["created_at"]),
    }


@router.get("/v1/admin/events/recent")
async def recent_events(
    request: Request,
    limit: int | None = Query(default=None),
) -> JSONResponse:
    """The `limit` most-recently-ingested events across ALL tenants, newest first.

    Operator-scoped, cross-tenant (ADR-0007 honesty boundary — this is coarser than the
    O-006 per-tenant `/v1/events` seam, by design: fleet triage needs a cross-tenant view).
    Metadata-only — never `payload`.
    """
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    limit_value = _clamp_limit(limit)
    async with get_privileged_session() as session:
        rows = await list_recent_events_admin(session, limit=limit_value)
    body = {"data": rows}
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


@router.get("/v1/admin/distributions/recent")
async def recent_distributions(
    request: Request,
    limit: int | None = Query(default=None),
) -> JSONResponse:
    """The `limit` most-recent policy distributions across ALL tenants, newest first.

    Operator-scoped, cross-tenant summary (distribution_id/policy_id/tenant_id/policy_type/
    state/created_at only) — never the signed policy body. An operator drills into one
    distribution's per-target detail via the existing
    `GET /v1/policies/distributions/{distribution_id}` seam.
    """
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    limit_value = _clamp_limit(limit)
    async with get_privileged_session() as session:
        rows = await list_recent_distributions_admin(session, limit=limit_value)
    body = {"data": [_distribution_summary_body(row) for row in rows]}
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


def _identity_event_summary_body(row: dict[str, Any]) -> dict[str, Any]:
    """Project one identity_events row for the admin fleet-triage read (O-010, ADR-0010)."""
    body: dict[str, Any] = {
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


@router.get("/v1/admin/identity/events/recent")
async def recent_identity_events(
    request: Request,
    limit: int | None = Query(default=None),
) -> JSONResponse:
    """The `limit` most-recent cross-product identity events across ALL tenants (O-010).

    Operator-scoped, cross-tenant fleet triage — the same shape as the two O-007 admin
    reads above. Same operator bearer (`ORCH_ADMIN_TOKEN`); a tenant's own scoped view is
    the existing `GET /v1/identity/events` seam (query_service_tokens principal).
    """
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    limit_value = _clamp_limit(limit)
    async with get_privileged_session() as session:
        rows = await list_recent_identity_events_admin(session, limit=limit_value)
    body = {"data": [_identity_event_summary_body(row) for row in rows]}
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


def _distribution_state_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        state = row["state"]
        counts[state] = counts.get(state, 0) + 1
    return counts


def _registry_audit_summary_body(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "sentinel_id": row["sentinel_id"],
        "action": row["action"],
        "disposition": row["disposition"],
        "error_reason": row.get("error_reason"),
        "created_at": _isoformat(row["created_at"]),
    }


@router.get("/v1/admin/dashboard/summary")
async def dashboard_summary(
    request: Request,
    limit: int | None = Query(default=None),
) -> JSONResponse:
    """A bounded operator command-dashboard summary (O-014, ADR-0014).

    Aggregates data the Orchestrator ALREADY tracks — no new tables, no new outbound calls:
    registry health/enabled counts (O-005), a state-count breakdown over the `limit` most
    recent policy distributions (O-004, the same bounded page `/v1/admin/distributions/recent`
    already serves), and the `limit` most recent auto-rollback registry-audit trips (O-014's
    own circuit-breaker, see `coordination.health`/`coordination.registry`) — the ordinary
    `disable` action, filtered to the AUTO_ROLLBACK_REASON_PREFIX `error_reason` a manual
    disable never sets.

    HONESTY BOUNDARY (verbatim, ADR-0014): this is NOT "system health, API loads, and
    governance metrics across all [four Anoryx] products" — the Orchestrator has no access to
    Sentinel/Delta/Rendly internals beyond what already flows through its own ingest/registry/
    distribution seams, and CLAUDE.md's protect-paths boundary means this repo's code must
    never reach into another product's tree to fetch more. It is a real, honest summary of
    what the Orchestrator itself already knows.
    """
    settings: CoordinationSettings = request.app.state.coordination_settings
    request_id = _request_id()
    auth_error = _require_admin(request, settings, request_id)
    if auth_error is not None:
        return auth_error
    limit_value = _clamp_limit(limit)
    async with get_privileged_session() as session:
        by_health_status = await count_sentinels_by_health_status(session)
        by_enabled = await count_sentinels_by_enabled(session)
        recent_distributions = await list_recent_distributions_admin(session, limit=limit_value)
        recent_rollbacks = await list_recent_registry_audit_admin(
            session,
            limit=limit_value,
            action="disable",
            error_reason_prefix=AUTO_ROLLBACK_REASON_PREFIX,
        )
    body = {
        "sentinels": {
            "total": sum(by_enabled.values()),
            "by_health_status": by_health_status,
            "by_enabled": by_enabled,
        },
        "recent_distributions": {
            "window": limit_value,
            "by_state": _distribution_state_counts(recent_distributions),
        },
        "recent_auto_rollbacks": {
            "window": limit_value,
            "count": len(recent_rollbacks),
            "events": [_registry_audit_summary_body(r) for r in recent_rollbacks],
        },
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


@router.get("/admin", include_in_schema=False)
async def admin_ui() -> HTMLResponse:
    """Serve the minimal static operator UI (registry + recent events + distribution status).

    No secret is embedded in the page; the operator's bearer token is entered client-side
    (kept only in the browser tab's memory) and attached to the three admin-gated fetches.
    """
    with open(os.path.join(_STATIC_DIR, "index.html"), encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
