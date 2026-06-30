"""POST + GET /v1/policies/distributions — the O-001 distribution seam (O-004, ADR-0004).

Mirrors the O-003 ingest router boundary discipline (src/orchestrator/ingest/router.py):
fail-closed bearer peer-auth, parse + structural validation, locked-schema policy validation,
a NUL guard (a \\x00 cannot be stored in Postgres text/JSONB), then a durable tenant-scoped
persist (the tenant session AUTOBEGINS — never a nested `session.begin()`; ADR-0026) plus a
privileged hash-chained audit link, then the async engine is scheduled as a FastAPI
BackgroundTask and the request returns 202. Any error below the auth boundary propagates to
the app fail-safe handler (503) — a non-durably-recorded distribution is never 202'd.

PEER AUTH IS COARSE-GRAINED (O-001 honesty boundary d): the inbound service token is a single
shared bearer, not per-tenant. Per-tenant authorization is O-006. The GET status read is
documented as a coarse-grained read in its handler docstring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

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

router = APIRouter()

_BEARER_PREFIX = "Bearer "
_MAX_TARGETS = 256
_SENTINEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ALLOWED_REQUEST_KEYS = frozenset({"policy", "targets", "sign_on_behalf"})


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _contains_nul(obj: object) -> bool:
    """Recursively detect a NUL (\\x00) in any string within *obj* (reused from the ingest
    boundary). Postgres `text` and JSONB both reject \\x00, so a NUL anywhere in the policy
    record would crash the persist insert (a non-IntegrityError → 503), leaving the
    distribution neither recorded nor rejected (retry storm). Such a record is rejected at the
    boundary as malformed (422), a deterministic terminal disposition (O-003 audit M-2 class).
    """
    if isinstance(obj, str):
        return "\x00" in obj
    if isinstance(obj, dict):
        return any(_contains_nul(k) or _contains_nul(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contains_nul(item) for item in obj)
    return False


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _require_bearer(
    request: Request, settings: DistributionSettings, request_id: str
) -> JSONResponse | None:
    """Fail-closed bearer peer-auth. Returns an error JSONResponse, or None on success.

    Missing / non-"Bearer " / empty Authorization → 401. If no inbound service token is
    configured the seam can NEVER match → 401 (fail-closed; an ingest-only deployment is not
    forced to configure distribution, but the request still requires the token). A present
    token that mismatches → 403. The compare is constant-time.
    """
    header = request.headers.get("Authorization", "")
    if not header.startswith(_BEARER_PREFIX):
        return _error(401, "unauthorized", "peer authentication required", request_id)
    presented = header[len(_BEARER_PREFIX) :]
    if not presented:
        return _error(401, "unauthorized", "peer authentication required", request_id)
    if settings.service_token is None:
        return _error(401, "unauthorized", "peer authentication required", request_id)
    if not hmac.compare_digest(presented, settings.service_token):
        return _error(403, "forbidden", "peer is not authorized", request_id)
    return None


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
    error bodies are exposed here", contract). last_attempt_at maps from distributed_at when
    present (the only per-attempt timestamp recorded).
    """
    target_bodies: list[dict[str, Any]] = []
    for target in targets:
        entry: dict[str, Any] = {"sentinel_id": target["sentinel_id"], "state": target["state"]}
        distributed_at = target.get("distributed_at")
        if distributed_at is not None:
            entry["last_attempt_at"] = _isoformat(distributed_at)
        target_bodies.append(entry)
    return {
        "distribution_id": dist["distribution_id"],
        "policy_id": dist["policy_id"],
        "state": dist["state"],
        "created_at": _isoformat(dist["created_at"]),
        "targets": target_bodies,
    }


@router.post("/v1/policies/distributions")
async def submit_distribution(request: Request, background: BackgroundTasks) -> JSONResponse:
    settings: DistributionSettings = request.app.state.distribution_settings
    request_id = _request_id()

    # 1. Peer auth (fail-closed).
    auth_error = _require_bearer(request, settings, request_id)
    if auth_error is not None:
        return auth_error

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
    if _contains_nul(policy):
        return _error(
            422, "schema_invalid", "policy contains a forbidden NUL character", request_id
        )

    # 6. Server-resolved identity — every locked oneOf variant requires these four fields, so
    #    schema validation guarantees their presence; tenant_id is NEVER a client header.
    tenant_id = policy["tenant_id"]
    policy_id = policy["policy_id"]
    policy_version = policy["policy_version"]
    policy_type = policy["policy_type"]

    # 7. Identity + content hash of the byte-identical signed record (canonical JSON).
    distribution_id = uuid.uuid4().hex
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
                    "target_id": uuid.uuid4().hex,
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
async def get_distribution_status(distribution_id: str, request: Request) -> JSONResponse:
    """Return DistributionStatus for *distribution_id* (COARSE-GRAINED read).

    The inbound service token is coarse-grained (a single shared bearer, not per-tenant — O-001
    honesty boundary d); per-tenant authorization is O-006. The path id carries no tenant and
    RLS needs the GUC set before a tenant read, so we first resolve the row's tenant_id under a
    PRIVILEGED (BYPASSRLS) session, then RE-READ the distribution + its targets under
    get_tenant_session(tenant_id) so the response is RLS-confirmed (the app role only sees the
    row if RLS admits it). A 404 is returned when the distribution is not visible under that
    tenant session. Honest scope: this is a coarse-grained read pending the per-tenant authz of
    O-006.
    """
    settings: DistributionSettings = request.app.state.distribution_settings
    request_id = _request_id()

    auth_error = _require_bearer(request, settings, request_id)
    if auth_error is not None:
        return auth_error

    # Resolve the owning tenant under the privileged session — the path id has no tenant
    # context and a tenant read needs the GUC set first.
    async with get_privileged_session() as psession:
        meta = await get_distribution(psession, distribution_id)
    if meta is None:
        return _error(404, "not_found", "distribution not found", request_id)
    tenant_id = meta["tenant_id"]

    # Re-read under the tenant session so the response is RLS-confirmed (fail-closed).
    async with get_tenant_session(tenant_id) as session:
        dist = await get_distribution(session, distribution_id)
        if dist is None:
            return _error(404, "not_found", "distribution not found", request_id)
        targets = await list_distribution_targets(session, distribution_id)

    return JSONResponse(
        status_code=200,
        content=_distribution_status_body(dist, targets),
        headers={"X-Request-Id": request_id},
    )
