"""GET /v1/admin/command-center/summary + POST /v1/admin/policy-distributions/rollback
(O-014, ADR-0014).

Two independent seams sharing the SAME operator bearer (`ORCH_ADMIN_TOKEN`,
`CoordinationSettings.admin_token`) that already fronts the O-005/O-007/O-013 admin
seams — no new trust root.

A. The summary (`GET /v1/admin/command-center/summary`) is a pure, read-only aggregation
   over metrics the Orchestrator ALREADY collects: multi-Sentinel registry health (O-005),
   policy-distribution outcomes (O-004), automation-rule executions (O-011), external-
   gateway access attempts (O-013), and raw ingest throughput (O-003) — all cross-tenant
   (operator fleet triage, mirrors admin/router.py). It does NOT reach into Delta or
   Rendly's own internals; there is no telemetry pipeline that pushes their data here.

B. The rollback action (`POST /v1/admin/policy-distributions/rollback`) re-submits the
   IMMEDIATELY PRIOR signed policy record for a given (tenant_id, policy_id) through the
   EXISTING O-004 distribution engine (verbatim reuse of insert_policy_distribution +
   insert_distribution_target + drive_distribution — no new dispatch logic). This is an
   OPERATOR-TRIGGERED action, never an autonomous one — see ADR-0014 for why "automated,
   failure-detection-triggered rollback" is explicitly out of scope for this PR.
"""

from __future__ import annotations

import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from orchestrator.boundary import contains_nul
from orchestrator.config import CommandCenterSettings, CoordinationSettings, DistributionSettings
from orchestrator.distribution.engine import drive_distribution
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_distribution_audit_link,
    append_rollback_audit_link,
    count_automation_executions_by_disposition_since,
    count_distributions_by_state_since,
    count_external_gateway_by_outcome_since,
    count_ingest_events_since,
    count_registry_by_status,
    count_rollbacks_since,
    insert_distribution_target,
    insert_policy_distribution,
    list_distribution_targets,
    list_recent_distributions_for_policy,
)

router = APIRouter()

_BEARER_PREFIX = "Bearer "
_MAX_TENANT_ID_LEN = 64
_MAX_POLICY_ID_LEN = 64
_ALLOWED_ROLLBACK_KEYS = frozenset({"tenant_id", "policy_id"})

# Closed enums (membership only) — zero-filled in the summary response so consumers get a
# stable shape regardless of which outcomes happened to occur in the lookback window.
_REGISTRY_STATUSES = ("unknown", "healthy", "degraded", "unreachable")
_DISTRIBUTION_STATES = ("pending", "distributed", "partial", "failed")
_AUTOMATION_DISPOSITIONS = ("executed", "failed")
_EXTERNAL_GATEWAY_OUTCOMES = ("allowed", "scope_denied", "rate_limited", "revoked")


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

    Byte-identical policy to `admin.router._require_admin` / `external_gateway.router.
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


def _zero_fill(counts: dict[str, int], known: tuple[str, ...]) -> dict[str, int]:
    """Zero-fill a closed enum so the response shape is stable regardless of which
    outcomes occurred in the lookback window. Any unexpected key from the DB (there
    should be none — these mirror CHECK constraints) is passed through unchanged rather
    than silently dropped."""
    filled = {key: 0 for key in known}
    filled.update(counts)
    return filled


@router.get("/v1/admin/command-center/summary")
async def command_center_summary(request: Request) -> JSONResponse:
    """A cross-tenant, read-only fleet-health snapshot (operator-gated).

    Aggregates ONLY what the Orchestrator's own tables already track over the configured
    lookback window (ORCH_COMMAND_CENTER_LOOKBACK_HOURS, default 24h) — registry health is
    a point-in-time count (not windowed; a Sentinel's health_status is itself already the
    latest known state, ADR-0005).
    """
    request_id = _request_id()
    coordination_settings: CoordinationSettings = request.app.state.coordination_settings
    auth_error = _require_admin(request, coordination_settings, request_id)
    if auth_error is not None:
        return auth_error

    settings: CommandCenterSettings = request.app.state.command_center_settings
    since = datetime.now(timezone.utc) - timedelta(hours=settings.lookback_hours)

    async with get_privileged_session() as session:
        registry = await count_registry_by_status(session)
        distributions = await count_distributions_by_state_since(session, since)
        automation = await count_automation_executions_by_disposition_since(session, since)
        external_gateway = await count_external_gateway_by_outcome_since(session, since)
        ingest_count = await count_ingest_events_since(session, since)
        rollback_count = await count_rollbacks_since(session, since)

    body = {
        "generated_at": _isoformat(datetime.now(timezone.utc)),
        "lookback_hours": settings.lookback_hours,
        "registry": _zero_fill(registry, _REGISTRY_STATUSES),
        "distributions": _zero_fill(distributions, _DISTRIBUTION_STATES),
        "automation_executions": _zero_fill(automation, _AUTOMATION_DISPOSITIONS),
        "external_gateway": _zero_fill(external_gateway, _EXTERNAL_GATEWAY_OUTCOMES),
        "ingest_events_count": ingest_count,
        "rollbacks_count": rollback_count,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


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


def _validate_rollback_body(body: dict[str, Any]) -> tuple[str, str] | None:
    """Structural validation of a POST /v1/admin/policy-distributions/rollback body.

    Returns (code, message) for a 422, or None when valid. Never touches the DB.
    """
    if set(body) - _ALLOWED_ROLLBACK_KEYS:
        return ("schema_invalid", "request contains unknown fields")
    if _ALLOWED_ROLLBACK_KEYS - set(body):
        return ("schema_invalid", "request is missing required fields")
    tenant_id = body.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > _MAX_TENANT_ID_LEN:
        return ("schema_invalid", "tenant_id is required")
    policy_id = body.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id or len(policy_id) > _MAX_POLICY_ID_LEN:
        return ("schema_invalid", "policy_id is required")
    return None


@router.post("/v1/admin/policy-distributions/rollback")
async def rollback_policy_distribution(
    request: Request, background: BackgroundTasks
) -> JSONResponse:
    """Roll back one (tenant_id, policy_id) to its immediately-prior distributed version
    (operator-gated).

    Re-submits the SECOND-most-recent distribution's `signed_record` byte-identically as
    a BRAND NEW distribution — the exact same persist/audit/dispatch path as an ordinary
    `POST /v1/policies/distributions` submission (no bespoke rollback dispatch logic).
    The new distribution targets the SAME sentinel_ids the prior distribution targeted.
    409 `nothing_to_roll_back_to` if fewer than two distributions exist for this
    (tenant_id, policy_id) pair (there is no earlier version to restore).
    """
    request_id = _request_id()
    coordination_settings: CoordinationSettings = request.app.state.coordination_settings
    auth_error = _require_admin(request, coordination_settings, request_id)
    if auth_error is not None:
        return auth_error

    body, error = await _parse_body(request, request_id)
    if error is not None:
        return error
    if body is None:
        raise RuntimeError("_parse_body returned neither a body nor an error")

    structural = _validate_rollback_body(body)
    if structural is not None:
        code, message = structural
        return _error(422, code, message, request_id)

    tenant_id = body["tenant_id"]
    policy_id = body["policy_id"]

    async with get_tenant_session(tenant_id) as session:
        recent = await list_recent_distributions_for_policy(session, policy_id=policy_id, limit=2)
        if len(recent) < 2:
            return _error(
                409,
                "nothing_to_roll_back_to",
                "fewer than two distributions exist for this policy_id; there is no "
                "earlier version to restore",
                request_id,
            )
        current, previous = recent[0], recent[1]
        prior_targets = await list_distribution_targets(session, previous["distribution_id"])

        new_distribution_id = str(uuid.uuid4())
        await insert_policy_distribution(
            session,
            {
                "distribution_id": new_distribution_id,
                "policy_id": policy_id,
                "policy_version": previous["policy_version"],
                "tenant_id": tenant_id,
                "policy_type": previous["policy_type"],
                "state": "pending",
                "signed_record": previous["signed_record"],
                "content_hash": previous["content_hash"],
            },
        )
        for target in prior_targets:
            await insert_distribution_target(
                session,
                {
                    "target_id": str(uuid.uuid4()),
                    "distribution_id": new_distribution_id,
                    "tenant_id": tenant_id,
                    "sentinel_id": target["sentinel_id"],
                    "state": "pending",
                    "attempt_count": 0,
                    "max_attempts": target["max_attempts"],
                },
            )
        await session.commit()

    async with get_privileged_session() as psession:
        async with psession.begin():
            await append_distribution_audit_link(
                psession,
                {
                    "distribution_id": new_distribution_id,
                    "policy_id": policy_id,
                    "tenant_id": tenant_id,
                    "policy_type": previous["policy_type"],
                },
                disposition="submitted",
            )
            await append_rollback_audit_link(
                psession,
                tenant_id=tenant_id,
                policy_id=policy_id,
                source_distribution_id=previous["distribution_id"],
                superseded_distribution_id=current["distribution_id"],
                new_distribution_id=new_distribution_id,
            )

    distribution_settings: DistributionSettings = request.app.state.distribution_settings
    background.add_task(
        drive_distribution, new_distribution_id, tenant_id, settings=distribution_settings
    )

    return JSONResponse(
        status_code=202,
        content={
            "distribution_id": new_distribution_id,
            "policy_id": policy_id,
            "state": "pending",
            "rolled_back_to_distribution_id": previous["distribution_id"],
            "superseded_distribution_id": current["distribution_id"],
        },
        headers={"X-Request-Id": request_id},
    )
