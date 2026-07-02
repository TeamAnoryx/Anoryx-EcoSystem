"""POST + GET /v1/policies/distributions — the O-001 distribution seam (O-004, ADR-0004).

Mirrors the O-003 ingest router boundary discipline (src/orchestrator/ingest/router.py):
fail-closed per-tenant auth, parse + structural validation, locked-schema policy validation,
a NUL guard (a \\x00 cannot be stored in Postgres text/JSONB), then a durable tenant-scoped
persist (the tenant session AUTOBEGINS — never a nested `session.begin()`; ADR-0026) plus a
privileged hash-chained audit link, then the async engine is scheduled as a FastAPI
BackgroundTask and the request returns 202. Any error below the auth boundary propagates to
the app fail-safe handler (503) — a non-durably-recorded distribution is never 202'd.

AUTH IS PER-TENANT (O-006, ADR-0006, retrofit): the seam now derives a per-tenant principal
from the presented Bearer via `require_tenant_principal` (the coarse `ORCH_SERVICE_TOKEN` no
longer grants these reads/writes). POST validates the signed body's `tenant_id` against the
principal (mismatch → 403, closes O-004 LOW-2). GET status runs the read under the principal's
RLS session — a cross-tenant lookup is a 404, not another tenant's row (closes O-004 LOW-1).
The distribution engine + persistence are consumed UNCHANGED.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse

from orchestrator.boundary import contains_nul
from orchestrator.config import DistributionSettings
from orchestrator.distribution.engine import drive_distribution
from orchestrator.persistence.database import get_privileged_session, get_tenant_session
from orchestrator.persistence.repositories import (
    append_distribution_audit_link,
    get_distribution,
    insert_distribution_target,
    insert_policy_distribution,
    list_distribution_targets,
)
from orchestrator.schema_validation import policy_schema_errors
from orchestrator.security import require_tenant_principal

router = APIRouter()

_MAX_TARGETS = 256
_SENTINEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ALLOWED_REQUEST_KEYS = frozenset({"policy", "targets", "sign_on_behalf"})


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _request_structure_error(body: dict[str, Any]) -> tuple[str, str] | None:
    """Structurally validate a PolicyDistributionRequest (additionalProperties:false).

    Returns (code, message) for a 422, or None when structurally valid. Mirrors the contract:
    required `policy` (object); optional `targets` (array, maxItems 256, each object {sentinel_id}
    matching ^[A-Za-z0-9._-]{1,128}$); optional `sign_on_behalf` constrained to false
    (enum:[false], honesty boundary b). The locked policy.schema.json deep-validation is a
    separate step.
    """
    if set(body) - _ALLOWED_REQUEST_KEYS:
        return ("schema_invalid", "request contains unknown fields")
    if not isinstance(body.get("policy"), dict):
        return ("schema_invalid", "policy is required and must be an object")
    if "sign_on_behalf" in body and body["sign_on_behalf"] is not False:
        return ("sign_on_behalf_disabled", "sign_on_behalf must be false")
    if "targets" in body:
        targets = body["targets"]
        if not isinstance(targets, list):
            return ("schema_invalid", "targets must be an array")
        if len(targets) > _MAX_TARGETS:
            return ("schema_invalid", "targets exceeds the maximum of 256")
        for target in targets:
            if not isinstance(target, dict) or set(target) - {"sentinel_id"}:
                return ("schema_invalid", "each target must be an object with only sentinel_id")
            sentinel_id = target.get("sentinel_id")
            if not isinstance(sentinel_id, str) or not _SENTINEL_ID_PATTERN.match(sentinel_id):
                return ("schema_invalid", "target sentinel_id is malformed")
    return None


def _resolve_target_ids(body: dict[str, Any], settings: DistributionSettings) -> list[str]:
    """Resolve the distribution's sentinel_ids (order-preserving, de-duplicated).

    Explicit request `targets` win; otherwise the static config map's keys are used (may be
    empty → a zero-target distribution that aggregates to `failed`). De-duplication keeps the
    per-target UNIQUE(distribution_id, sentinel_id) constraint idempotent rather than 503'ing
    on a repeated id.
    """
    if "targets" in body:
        candidates = [t["sentinel_id"] for t in body["targets"]]
    else:
        candidates = list(settings.targets.keys())
    seen: set[str] = set()
    resolved: list[str] = []
    for sentinel_id in candidates:
        if sentinel_id not in seen:
            seen.add(sentinel_id)
            resolved.append(sentinel_id)
    return resolved


def _isoformat(value: object) -> str:
    """Render a datetime as an RFC 3339 / ISO 8601 string (contract date-time, maxLength 64)."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _distribution_status_body(
    dist: dict[str, Any], targets: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build a contract-conformant DistributionStatus (additionalProperties:false).

    Fields match openapi.yaml DistributionStatus / DistributionTargetStatus EXACTLY: parent
    {distribution_id, policy_id, state, created_at, targets[]}; each target {sentinel_id, state,
    last_attempt_at?}. Per-target last_error / attempt_count are deliberately NOT surfaced ("No
    error bodies are exposed here", contract). last_attempt_at ("if any", contract) is
    distributed_at on success, else the row's updated_at once an attempt has been recorded
    (attempt_count > 0 or state moved off 'pending'); it is omitted while the target is still
    the untouched insert-time row (pending, attempt_count 0 — no attempt yet).
    """
    target_bodies: list[dict[str, Any]] = []
    for target in targets:
        entry: dict[str, Any] = {"sentinel_id": target["sentinel_id"], "state": target["state"]}
        distributed_at = target.get("distributed_at")
        if distributed_at is not None:
            entry["last_attempt_at"] = _isoformat(distributed_at)
        elif target.get("attempt_count", 0) > 0 or target.get("state") != "pending":
            updated_at = target.get("updated_at")
            if updated_at is not None:
                entry["last_attempt_at"] = _isoformat(updated_at)
        target_bodies.append(entry)
    return {
        "distribution_id": dist["distribution_id"],
        "policy_id": dist["policy_id"],
        "state": dist["state"],
        "created_at": _isoformat(dist["created_at"]),
        "targets": target_bodies,
    }


@router.post("/v1/policies/distributions")
async def submit_distribution(
    request: Request,
    background: BackgroundTasks,
    principal: str = Depends(require_tenant_principal),
) -> JSONResponse:
    settings: DistributionSettings = request.app.state.distribution_settings
    request_id = _request_id()

    # 1. Per-tenant auth resolved by the require_tenant_principal dependency (fail-closed 401).

    # 2. Parse JSON → 422 on malformed / non-object.
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(body, dict):
        return _error(422, "schema_invalid", "request body must be a JSON object", request_id)

    # 3. Structural PolicyDistributionRequest validation.
    structural = _request_structure_error(body)
    if structural is not None:
        code, message = structural
        return _error(422, code, message, request_id)

    policy = body["policy"]

    # 4. Locked-schema policy validation (structural guard, not a trust decision).
    if policy_schema_errors(policy):
        return _error(422, "policy_schema_invalid", "policy failed schema validation", request_id)

    # 5. NUL guard — a \x00 cannot be stored, so it can be neither persisted nor recorded.
    if contains_nul(policy):
        return _error(
            422, "schema_invalid", "policy contains a forbidden NUL character", request_id
        )

    # 6. Server-resolved identity — every locked oneOf variant requires these four fields, so
    #    schema validation guarantees their presence; tenant_id is NEVER a client header.
    tenant_id = policy["tenant_id"]
    policy_id = policy["policy_id"]
    policy_version = policy["policy_version"]
    policy_type = policy["policy_type"]

    # 6b. Inbound tenant binding (O-006 Fork C, closes O-004 LOW-2): the signed body's tenant_id
    #     is VALIDATED against the authenticated principal, not trusted. A mismatch is rejected
    #     fail-closed (403) — a shared-token holder can no longer store a distribution under an
    #     arbitrary tenant.
    if tenant_id != principal:
        return _error(
            403,
            "forbidden",
            "policy tenant_id does not match the authenticated principal",
            request_id,
        )

    # 7. Identity + content hash of the byte-identical signed record (canonical JSON).
    #    distribution_id is an RFC-4122 hyphenated UUID (contract `format: uuid`).
    distribution_id = str(uuid.uuid4())
    content_hash = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    # 8. Resolve targets (explicit request list, else the static config map; may be empty).
    sentinel_ids = _resolve_target_ids(body, settings)

    # 9. Persist (tenant session AUTOBEGINS — NO `async with session.begin()`; ADR-0026).
    async with get_tenant_session(tenant_id) as session:
        await insert_policy_distribution(
            session,
            {
                "distribution_id": distribution_id,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "tenant_id": tenant_id,
                "policy_type": policy_type,
                "state": "pending",
                "signed_record": policy,
                "content_hash": content_hash,
            },
        )
        for sentinel_id in sentinel_ids:
            await insert_distribution_target(
                session,
                {
                    "target_id": str(uuid.uuid4()),
                    "distribution_id": distribution_id,
                    "tenant_id": tenant_id,
                    "sentinel_id": sentinel_id,
                    "state": "pending",
                    "attempt_count": 0,
                    "max_attempts": settings.max_attempts,
                },
            )
        await session.commit()

    # 10. Audit submit (privileged session does NOT autobegin → open the begin here).
    async with get_privileged_session() as psession:
        async with psession.begin():
            await append_distribution_audit_link(
                psession,
                {
                    "distribution_id": distribution_id,
                    "policy_id": policy_id,
                    "tenant_id": tenant_id,
                    "policy_type": policy_type,
                },
                disposition="submitted",
            )

    # 11. Schedule the async fan-out engine; 12. respond 202 DistributionAccepted.
    background.add_task(drive_distribution, distribution_id, tenant_id, settings=settings)
    return JSONResponse(
        status_code=202,
        content={"distribution_id": distribution_id, "policy_id": policy_id, "state": "pending"},
        headers={"X-Request-Id": request_id},
    )


@router.get("/v1/policies/distributions/{distribution_id}")
async def get_distribution_status(
    distribution_id: str,
    principal: str = Depends(require_tenant_principal),
) -> JSONResponse:
    """Return DistributionStatus for *distribution_id* (TENANT-SCOPED read, O-006, closes LOW-1).

    The caller's per-tenant principal is derived from the Bearer (require_tenant_principal); the
    read runs DIRECTLY under get_tenant_session(principal), so RLS returns the row only if it
    belongs to that tenant. A cross-tenant (or absent) id is indistinguishable from not-found —
    a 404, never another tenant's metadata and never an existence oracle. The old privileged
    pre-resolve (the O-004 LOW-1 hole) is gone. READ-ONLY METADATA (honesty boundary c): no
    policy body, no mutation.
    """
    request_id = _request_id()

    # Read under the principal's tenant session — RLS is the structural scope (no privileged
    # pre-resolve). Not visible under the principal's RLS → 404.
    async with get_tenant_session(principal) as session:
        dist = await get_distribution(session, distribution_id)
        if dist is None:
            return _error(404, "not_found", "distribution not found", request_id)
        targets = await list_distribution_targets(session, distribution_id)

    return JSONResponse(
        status_code=200,
        content=_distribution_status_body(dist, targets),
        headers={"X-Request-Id": request_id},
    )
