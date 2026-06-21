"""Admin operator control surface (F-012a, ADR-0014 §7 D6).

Thin control over the existing engines — REUSE, never reimplement (R7):
  GET   /admin/tenants/{id}/config             -> TenantRoutingPolicyRepository.get_config_row
  PATCH /admin/tenants/{id}/config             -> bounded update (admin_config_updated)
  GET   /admin/tenants/{id}/policies           -> PolicyRepository.list_for_tenant
  POST  /admin/tenants/{id}/compliance/evidence-> F-011 generate_evidence (operator path)

All cross-tenant reads emit admin_audit_accessed; the config write emits
admin_config_updated (R1/R6). Reads/writes are RLS-scoped to the TARGET tenant via
get_tenant_session(target). The compliance call reuses F-011's engine unchanged
(generate_evidence opens its own RLS session for the target).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError

from admin.audit import emit_admin_event
from admin.schemas import (
    ConfigResponse,
    ConfigUpdateRequest,
    OperatorEvidenceRequest,
    PolicyListResponse,
    PolicyResponse,
)
from admin.scope import enforce_admin_scope
from admin.util import actor_id, parse_body, request_id, validate_tenant_id_path
from compliance.constants import DISCLAIMER
from compliance.errors import EvidenceWindowError
from compliance.evidence import generate_evidence, validate_window
from compliance.gap_analysis import analyze_gaps
from compliance.mapping import load_framework
from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.policy_repository import PolicyRepository
from persistence.repositories.tenant_routing_policy_repository import TenantRoutingPolicyRepository

# Router deps: validate the path tenant_id, then enforce the operator's tenant-pin
# + role (ADR-0017 §3 D2, R1). require_admin runs at the parent admin_router.
control_router = APIRouter(
    tags=["admin"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)


async def _emit_access(
    tenant_id: str, request_id_val: str, actor_id_val: str | None = None
) -> None:
    """Append admin_audit_accessed for an operator cross-tenant read (R1, D8).

    actor_id_val (F-014 D9) attributes the read to the SSO operator (their
    admin_users.id) when present; None for break-glass (exact F-012a behavior).
    """
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_audit_accessed",
                target_tenant_id=tenant_id,
                request_id=request_id_val,
                actor_id=actor_id_val,
            )


def _parse_dt(value: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 datetime; 400 on failure."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
        except ValueError:
            continue
    raise HTTPException(status_code=400, detail="invalid_datetime")


@control_router.get("/tenants/{tenant_id}/config", response_model=ConfigResponse)
async def get_config(tenant_id: str, request: Request) -> ConfigResponse:
    """View a tenant's F-007/F-009 config (classifier / audit mode / team RPM)."""
    rid = request_id(request)
    async with get_tenant_session(tenant_id) as ts:
        row = await TenantRoutingPolicyRepository(ts).get_config_row(
            tenant_id, caller_tenant_id=tenant_id
        )
        if row is None:
            resp = ConfigResponse(
                tenant_id=tenant_id,
                classifier_model_id=None,
                audit_mode=None,
                team_rpm_limit=None,
                configured=False,
            )
        else:
            resp = ConfigResponse(
                tenant_id=tenant_id,
                classifier_model_id=row.classifier_model_id,
                audit_mode=row.audit_mode,
                team_rpm_limit=row.team_rpm_limit,
                configured=True,
            )
    await _emit_access(tenant_id, rid, actor_id(request))
    return resp


@control_router.patch("/tenants/{tenant_id}/config", response_model=ConfigResponse)
async def update_config(tenant_id: str, request: Request) -> ConfigResponse:
    """Adjust a tenant's F-007/F-009 config (bounded by the table's CHECK constraints)."""
    body = await parse_body(request, ConfigUpdateRequest)
    rid = request_id(request)
    aid = actor_id(request)
    updates = {k: getattr(body, k) for k in body.model_fields_set}
    if not updates:
        raise HTTPException(status_code=400, detail="no_fields")

    async with get_tenant_session(tenant_id) as ts:
        repo = TenantRoutingPolicyRepository(ts)
        try:
            row = await repo.update_config(tenant_id, caller_tenant_id=tenant_id, updates=updates)
        except IntegrityError:
            # A value violated a CHECK constraint (e.g. classifier allow-list).
            # Contract response set for this path is 400 (not 422).
            raise HTTPException(status_code=400, detail="invalid_config_value") from None
        if row is None:
            raise HTTPException(status_code=404, detail="no_routing_policy")
        resp = ConfigResponse(
            tenant_id=tenant_id,
            classifier_model_id=row.classifier_model_id,
            audit_mode=row.audit_mode,
            team_rpm_limit=row.team_rpm_limit,
            configured=True,
        )
        await ts.commit()

    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_config_updated",
                target_tenant_id=tenant_id,
                request_id=rid,
                actor_id=aid,
            )
    return resp


@control_router.get("/tenants/{tenant_id}/policies", response_model=PolicyListResponse)
async def list_policies(
    tenant_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> PolicyListResponse:
    """View a tenant's policy intake status (current policies). Reuses F-008 store."""
    rid = request_id(request)
    aid = actor_id(request)
    async with get_tenant_session(tenant_id) as ts:
        rows = await PolicyRepository(ts).list_for_tenant(tenant_id, limit=limit, offset=offset)
        policies = [PolicyResponse.model_validate(r) for r in rows]
    await _emit_access(tenant_id, rid, aid)
    return PolicyListResponse(policies=policies, count=len(policies))


@control_router.post("/tenants/{tenant_id}/compliance/evidence")
async def operator_generate_evidence(tenant_id: str, request: Request) -> dict[str, Any]:
    """Generate an audit-ready compliance evidence summary for a TARGET tenant.

    Reuses F-011's generate_evidence (the operator path deferred by ADR-0013); the
    engine opens its own RLS session scoped to the target. Cross-tenant read -> audited.
    """
    body = await parse_body(request, OperatorEvidenceRequest)
    rid = request_id(request)
    aid = actor_id(request)
    t0, t1 = _parse_dt(body.t0), _parse_dt(body.t1)
    try:
        validate_window(t0, t1)
    except EvidenceWindowError:
        raise HTTPException(status_code=400, detail="invalid_window") from None

    framework_map = load_framework(body.framework)
    projection = await generate_evidence(framework_map, t0, t1, tenant_id=tenant_id)
    gap = analyze_gaps(framework_map, projection)

    await _emit_access(tenant_id, rid, aid)
    return {
        "tenant_id": tenant_id,
        "framework": gap.framework,
        "framework_version": gap.framework_version,
        "window": {"t0": body.t0, "t1": body.t1},
        "readiness_score": gap.readiness,
        "totals": {
            "total": gap.total,
            "passed": gap.passed,
            "gap": gap.gap,
            "not_applicable": gap.not_applicable,
            "not_covered": gap.not_covered,
            "applicable": gap.applicable,
        },
        "disclaimer": DISCLAIMER,
    }
