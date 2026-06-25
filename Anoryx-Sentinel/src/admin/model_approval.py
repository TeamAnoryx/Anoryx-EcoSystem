"""Operator model-approval endpoints (F-019, ADR-0022 §5 / scope item 5).

Operator-only control over a TARGET tenant's model inventory — mirrors the F-012a
admin control surface (REUSE, never reimplement; R8):

  GET  /admin/tenants/{id}/models          -> ModelInventoryRepository.list_for_tenant
  POST /admin/tenants/{id}/models/approve  -> adopt-if-absent + transition -> approved
  POST /admin/tenants/{id}/models/deny     -> adopt-if-absent + transition -> denied

Operator-only + non-forgeable (R1): require_admin runs at the parent admin_router;
enforce_admin_scope pins an SSO operator to its own tenant + gates writes to
tenant_admin (auditor is read-only). A data-plane virtual-API-key caller can never
reach this router — it is mounted under admin auth, not /v1. The decision is
attributed to the authenticated operator (actor_id) + the TARGET tenant, never
nil-UUID and never the tenant's own identity (R6).

ATOMICITY (ADR-0022 §7.4): a transition and its audit must not diverge. The audit
log append needs a PRIVILEGED session (hash-chain reads the global tip across
tenants); the inventory write needs the TARGET tenant RLS session — two connections,
so true 2-phase atomicity is impossible. Instead the audit is committed BEFORE the
state: emit (privileged, commit) -> then commit the tenant state. A crash/failure
after the audit commit leaves at worst a safe over-audit (a logged decision that did
not take); it can NEVER leave a committed state change without a committed audit row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from admin.audit import emit_admin_event
from admin.scope import enforce_admin_scope
from admin.util import actor_id, parse_body, request_id, validate_tenant_id_path
from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.model_inventory_repository import (
    InvalidModelTransitionError,
    ModelInventory,
    ModelInventoryNotFoundError,
    ModelInventoryRepository,
)

# Same dependency stack as control_router: validate the path tenant_id, then enforce
# the operator tenant-pin + role. require_admin runs at the parent admin_router.
model_approval_router = APIRouter(
    tags=["admin"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)


class ModelDecisionRequest(BaseModel):
    """Body for approve/deny: the model to act on (+ its type when first adopted)."""

    # protected_namespaces=() — the fields begin with "model_"; without this Pydantic
    # warns about its reserved "model_" namespace (harmless here, but noisy in CI).
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    model_id: str = Field(min_length=1, max_length=256)
    model_type: Literal["base", "fine_tune"] = "base"


class ModelRetireRequest(BaseModel):
    """Body for retire: the approved model + its grace deadline (must be future).

    F-021 (ADR-0024). retire_at is parsed as a timezone-aware instant; a past/now
    value is rejected (400) by the endpoint so retirement is only ever a real future
    grace window (immediate blocks use deny, not retire).
    """

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    model_id: str = Field(min_length=1, max_length=256)
    retire_at: datetime


class ModelInventoryItem(BaseModel):
    """One inventory row in the list response."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    model_id: str
    model_type: str
    state: str
    approved_by: str | None
    approved_at: str | None
    # F-021 (ADR-0024): grace deadline (ISO-8601 Z), or null when not retiring. The UI
    # derives a "retiring — usable until <date>" label from (state=approved + retire_at).
    retire_at: str | None
    created_at: str | None
    updated_at: str | None


class ModelInventoryListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    models: list[ModelInventoryItem]
    count: int


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt is not None else None


def _to_item(row: ModelInventory) -> ModelInventoryItem:
    return ModelInventoryItem(
        model_id=row.model_id,
        model_type=row.model_type,
        state=row.state,
        approved_by=row.approved_by,
        approved_at=_iso(row.approved_at),
        retire_at=_iso(row.retire_at),
        created_at=_iso(row.created_at),
        updated_at=_iso(row.updated_at),
    )


@model_approval_router.get("/tenants/{tenant_id}/models", response_model=ModelInventoryListResponse)
async def list_models(
    tenant_id: str,
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> ModelInventoryListResponse:
    """List a target tenant's model inventory (operator read; cross-tenant -> audited)."""
    rid = request_id(request)
    aid = actor_id(request)
    async with get_tenant_session(tenant_id) as ts:
        rows = await ModelInventoryRepository(ts).list_for_tenant(
            tenant_id, limit=limit, offset=offset
        )
    # Cross-tenant operator read -> admin_audit_accessed (R1/D8), same as control.py.
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_audit_accessed",
                target_tenant_id=tenant_id,
                request_id=rid,
                actor_id=aid,
            )
    return ModelInventoryListResponse(
        tenant_id=tenant_id, models=[_to_item(r) for r in rows], count=len(rows)
    )


async def _decide(
    tenant_id: str, request: Request, *, new_state: str, decision_event: str
) -> ModelInventoryItem:
    """Shared approve/deny path: adopt-if-absent, transition, audit-then-commit.

    Emits model_adopted ONLY when this action newly registers the model (honest:
    the row did not exist before), then the decision event (model_approved /
    model_denied). Both audit appends commit in ONE privileged transaction BEFORE
    the tenant state commit (ADR-0022 §7.4 audit-before-state invariant).
    """
    body = await parse_body(request, ModelDecisionRequest)
    rid = request_id(request)
    aid = actor_id(request)
    now = datetime.now(UTC)

    async with get_tenant_session(tenant_id) as ts:
        repo = ModelInventoryRepository(ts)
        # adopt returns created=True only if it inserted a new row — gate the
        # model_adopted event on that, not a separate pre-adopt read (no TOCTOU).
        _, created = await repo.adopt(tenant_id, body.model_id, body.model_type)
        try:
            row = await repo.transition(
                tenant_id, body.model_id, new_state, operator_id=aid, now=now
            )
        except InvalidModelTransitionError as exc:
            # e.g. already in the requested state, or an illegal edge. 409 conflict.
            raise HTTPException(status_code=409, detail="invalid_model_transition") from exc

        # Audit FIRST (privileged, committed) — before the tenant state commit.
        async with get_privileged_session() as ps:
            async with ps.begin():
                if created:
                    await emit_admin_event(
                        ps,
                        event_type="model_adopted",
                        target_tenant_id=tenant_id,
                        request_id=rid,
                        actor_id=aid,
                        model=body.model_id,
                    )
                await emit_admin_event(
                    ps,
                    event_type=decision_event,
                    target_tenant_id=tenant_id,
                    request_id=rid,
                    actor_id=aid,
                    model=body.model_id,
                )
        # THEN commit the inventory state.
        await ts.commit()
        return _to_item(row)


@model_approval_router.post(
    "/tenants/{tenant_id}/models/approve", response_model=ModelInventoryItem
)
async def approve_model(tenant_id: str, request: Request) -> ModelInventoryItem:
    """Transition a model to 'approved' (adopting it first if not yet in inventory)."""
    return await _decide(tenant_id, request, new_state="approved", decision_event="model_approved")


@model_approval_router.post("/tenants/{tenant_id}/models/deny", response_model=ModelInventoryItem)
async def deny_model(tenant_id: str, request: Request) -> ModelInventoryItem:
    """Transition a model to 'denied' (adopting it first if not yet in inventory)."""
    return await _decide(tenant_id, request, new_state="denied", decision_event="model_denied")


@model_approval_router.post("/tenants/{tenant_id}/models/retire", response_model=ModelInventoryItem)
async def retire_model(tenant_id: str, request: Request) -> ModelInventoryItem:
    """Schedule retirement of an APPROVED model with a grace deadline (operator-only).

    F-021 (ADR-0024). Backend-ENFORCED: after retire_at the model is denied at the
    gateway, fail-closed (src/policy/enforcement.py). Only an 'approved' model can be
    retired — pending/denied/absent → 409 (`invalid_model_transition`) / 404. The
    deadline must be in the future (else 400). Audit FIRST (privileged, committed) →
    then commit the tenant state (ADR-0022 §7.4 audit-before-state invariant). The
    target tenant is the PATH parameter; the decision is attributed to the operator
    (actor_id) + the TARGET tenant. Metadata only — never weights, secrets, or PII.
    """
    body = await parse_body(request, ModelRetireRequest)
    rid = request_id(request)
    aid = actor_id(request)
    now = datetime.now(UTC)

    # Normalize to an aware UTC instant; a naive value is read as UTC (contract: RFC3339
    # UTC). A past/now deadline would deny immediately — reject so retire is always a
    # real future grace window (immediate blocks use deny).
    retire_at = body.retire_at
    if retire_at.tzinfo is None:
        retire_at = retire_at.replace(tzinfo=UTC)
    if retire_at <= now:
        raise HTTPException(status_code=400, detail="retire_at_must_be_future")

    async with get_tenant_session(tenant_id) as ts:
        repo = ModelInventoryRepository(ts)
        try:
            row = await repo.set_retirement(tenant_id, body.model_id, retire_at, now=now)
        except ModelInventoryNotFoundError as exc:
            raise HTTPException(status_code=404, detail="model_not_found") from exc
        except InvalidModelTransitionError as exc:
            # Model is not in 'approved' state — only approved models can be retired.
            raise HTTPException(status_code=409, detail="invalid_model_transition") from exc

        # Audit FIRST (privileged, committed) — before the tenant state commit.
        async with get_privileged_session() as ps:
            async with ps.begin():
                await emit_admin_event(
                    ps,
                    event_type="model_retirement_scheduled",
                    target_tenant_id=tenant_id,
                    request_id=rid,
                    actor_id=aid,
                    model=body.model_id,
                )
        await ts.commit()
        return _to_item(row)


@model_approval_router.post(
    "/tenants/{tenant_id}/models/unretire", response_model=ModelInventoryItem
)
async def unretire_model(tenant_id: str, request: Request) -> ModelInventoryItem:
    """Cancel a scheduled retirement (clears the grace deadline; operator-only).

    F-021 (ADR-0024). Rejects a model with no scheduled retirement → 409
    (`invalid_model_transition`) / 404 if absent. Same audit-before-state ordering as
    retire. Reuses the approve/deny request body (model_id only). Metadata only.
    """
    body = await parse_body(request, ModelDecisionRequest)
    rid = request_id(request)
    aid = actor_id(request)
    now = datetime.now(UTC)

    async with get_tenant_session(tenant_id) as ts:
        repo = ModelInventoryRepository(ts)
        try:
            row = await repo.clear_retirement(tenant_id, body.model_id, now=now)
        except ModelInventoryNotFoundError as exc:
            raise HTTPException(status_code=404, detail="model_not_found") from exc
        except InvalidModelTransitionError as exc:
            raise HTTPException(status_code=409, detail="invalid_model_transition") from exc

        async with get_privileged_session() as ps:
            async with ps.begin():
                await emit_admin_event(
                    ps,
                    event_type="model_retirement_cancelled",
                    target_tenant_id=tenant_id,
                    request_id=rid,
                    actor_id=aid,
                    model=body.model_id,
                )
        await ts.commit()
        return _to_item(row)
