"""Webhook-config admin CRUD surface (F-020, ADR-0023 §5.2 / §5.5).

Per-tenant control over a tenant's outbound webhook configuration (Slack / Jira /
Splunk integration suite) — mounted under the F-012a admin console (REUSE, never
reimplement; R8), mirroring model_approval (F-019):

  POST   /admin/tenants/{id}/webhooks                -> create a webhook_config
  GET    /admin/tenants/{id}/webhooks                -> list the tenant's configs
  GET    /admin/tenants/{id}/webhooks/{config_id}    -> get one config (metadata)
  PATCH  /admin/tenants/{id}/webhooks/{config_id}    -> update (incl. rotate secrets)
  DELETE /admin/tenants/{id}/webhooks/{config_id}    -> SOFT-delete (enabled=false)

AUTH (R1, non-forgeable): require_admin runs at the parent admin_router;
enforce_admin_scope pins an SSO operator to its own tenant + gates writes to
tenant_admin (a tenant_auditor is read-only: GET allowed, write -> 403). A
data-plane virtual-API-key caller can never reach this router — it is mounted under
admin auth, not /v1. Every CRUD action is attributed to the authenticated operator
(actor_id) + the TARGET tenant (target_tenant_id), never nil-UUID and never the
tenant's own identity (R6).

SECRETS (R4/R6, non-negotiables #4/#6):
  * credential and signing_secret are accepted in create/update bodies as PLAINTEXT
    (over TLS) and encrypted IMMEDIATELY via admin.sso.secret_box.encrypt before any
    persistence. Only the AES-256-GCM ciphertext blob is ever stored.
  * The response NEVER echoes either secret — only the booleans has_credential /
    has_signing_secret reveal presence. No decrypted value is logged anywhere.

SSRF (the load-bearing control, §7): every create/update target_url is validated
through the F-020 url_guard (orchestration.webhooks.url_guard.check_url) at config
time. A denied URL (private/reserved/loopback/non-https/bad-port/unresolvable) is
rejected with 422 and NOTHING is persisted — stopping an SSRF config from ever
reaching the DB, in addition to the send-time re-validation the dispatcher performs.

DELETE semantics (ADR §5.2): the webhook_config table has NO DELETE path — its
model docstring states "No DELETE path — use enabled=False to disable
(soft-disable). The GRANT covers SELECT, INSERT, UPDATE to sentinel_app only," and
the ADR lists no deleted_at column. So DELETE is a SOFT-delete: set enabled=False
(auditable, reversible by re-enabling) and emit config_action="deleted".

SESSION SHAPE (mirrors keys.py / model_approval.py EXACTLY): the config write runs on
the TARGET tenant RLS session (get_tenant_session) and is committed there; the
audit append needs the PRIVILEGED session (the hash chain reads the global tip
across tenants), so emit_admin_event runs in a SEPARATE get_privileged_session()
under `async with ps.begin():`. get_tenant_session AUTOBEGINS — never call
session.begin() on it (F-008/F-019 double-begin 500); writes commit explicitly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select

from admin.audit import emit_admin_event
from admin.schemas import (
    WebhookConfigCreate,
    WebhookConfigListResponse,
    WebhookConfigResponse,
    WebhookConfigUpdate,
)
from admin.scope import enforce_admin_scope
from admin.sso.secret_box import encrypt
from admin.util import actor_id, parse_body, request_id, validate_tenant_id_path
from orchestration.webhooks.url_guard import check_url
from persistence.database import get_privileged_session, get_tenant_session
from persistence.models.webhook_config import WebhookConfig

# Same dependency stack as the other per-tenant admin routers (keys / control /
# model_approval): validate the path tenant_id, then pin the operator + role-gate.
# require_admin runs at the parent admin_router.
webhooks_router = APIRouter(
    tags=["admin"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)


def _to_response(row: WebhookConfig) -> WebhookConfigResponse:
    """Project an ORM row to the metadata response — NEVER the secret blobs (R4/R6).

    credential / signing_secret presence is surfaced as a boolean only; the
    ciphertext (let alone the plaintext) never leaves the gateway.
    """
    return WebhookConfigResponse(
        config_id=row.config_id,
        tenant_id=row.tenant_id,
        provider=row.provider,
        target_url=row.target_url,
        min_severity=row.min_severity,
        enabled=row.enabled,
        team_id=row.team_id,
        project_id=row.project_id,
        has_credential=row.credential is not None,
        has_signing_secret=row.signing_secret is not None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _guard_target_url(target_url: str) -> None:
    """Reject an SSRF-unsafe target_url at config time with 422 (nothing persisted).

    Runs the F-020 url_guard BEFORE any write. A deny (private/reserved/loopback/
    link-local/non-https/bad-port/unresolvable host) raises 422 — the config never
    reaches the DB. The deny reason slug is bounded and topology-safe; it carries no
    resolved IP. This is the config-time half of defence-in-depth; the dispatcher
    re-validates (resolve-and-pin) at send time.
    """
    result = check_url(target_url)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"target_url_rejected:{result.reason}",
        )


async def _emit_config_event(
    *, tenant_id: str, request: Request, provider: str, config_action: str
) -> None:
    """Append a webhook_config_updated audit event on a fresh privileged session.

    Mirrors keys.py / control.py: a SEPARATE get_privileged_session() under
    `async with ps.begin():` (the hash chain requires the privileged role to read
    the global tip). Metadata only — provider + action; NEVER the URL/credential/
    signing-secret (D1/non-neg #6).
    """
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="webhook_config_updated",
                target_tenant_id=tenant_id,
                request_id=request_id(request),
                actor_id=actor_id(request),
                webhook_provider=provider,
                config_action=config_action,
            )


@webhooks_router.post(
    "/tenants/{tenant_id}/webhooks",
    response_model=WebhookConfigResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_webhook_config(tenant_id: str, request: Request) -> WebhookConfigResponse:
    """Create a webhook config for the target tenant (SSRF-guarded, secrets encrypted)."""
    body = await parse_body(request, WebhookConfigCreate)

    # SSRF guard BEFORE any persistence — a denied URL never reaches the DB.
    _guard_target_url(body.target_url)

    # Encrypt write-only secrets immediately; only ciphertext is ever stored (R6).
    credential_ct = encrypt(body.credential) if body.credential is not None else None
    signing_secret_ct = encrypt(body.signing_secret) if body.signing_secret is not None else None

    config_id = str(uuid.uuid4())
    async with get_tenant_session(tenant_id) as ts:
        row = WebhookConfig(
            config_id=config_id,
            tenant_id=tenant_id,
            provider=body.provider,
            target_url=body.target_url,
            credential=credential_ct,
            signing_secret=signing_secret_ct,
            min_severity=body.min_severity,
            enabled=body.enabled,
            team_id=body.team_id,
            project_id=body.project_id,
        )
        ts.add(row)
        # Build the response BEFORE commit: get_tenant_session sets app.current_tenant_id
        # via SET LOCAL, which Postgres clears at commit. flush() executes the INSERT
        # (populating server defaults + PK) under the still-live RLS GUC; _to_response
        # reads the populated attributes here. A post-commit refresh() would re-SELECT
        # with no tenant GUC -> RLS hides the row -> 0 rows -> 500. (Found by F-020 vector tests.)
        await ts.flush()
        resp = _to_response(row)
        await ts.commit()

    await _emit_config_event(
        tenant_id=tenant_id, request=request, provider=body.provider, config_action="created"
    )
    return resp


@webhooks_router.get("/tenants/{tenant_id}/webhooks", response_model=WebhookConfigListResponse)
async def list_webhook_configs(
    tenant_id: str,
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> WebhookConfigListResponse:
    """List the target tenant's webhook configs (metadata only — never secrets)."""
    async with get_tenant_session(tenant_id) as ts:
        stmt = (
            select(WebhookConfig)
            .where(WebhookConfig.tenant_id == tenant_id)
            .order_by(WebhookConfig.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = list((await ts.execute(stmt)).scalars().all())
    configs = [_to_response(r) for r in rows]
    return WebhookConfigListResponse(configs=configs, count=len(configs))


async def _load_config(ts, tenant_id: str, config_id: str) -> WebhookConfig:
    """Fetch a single config under the tenant RLS session (explicit predicate = 2nd lock).

    Returns the row or raises 404. The RLS policy plus the explicit tenant_id
    predicate both scope the lookup to the caller's tenant (a config_id belonging to
    another tenant is invisible here -> 404, never cross-tenant disclosure).
    """
    stmt = select(WebhookConfig).where(
        WebhookConfig.tenant_id == tenant_id,
        WebhookConfig.config_id == config_id,
    )
    row = (await ts.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="webhook_config_not_found"
        )
    return row


@webhooks_router.get(
    "/tenants/{tenant_id}/webhooks/{config_id}", response_model=WebhookConfigResponse
)
async def get_webhook_config(
    tenant_id: str, config_id: str, request: Request
) -> WebhookConfigResponse:
    """Get a single webhook config by id (metadata only — never secrets)."""
    async with get_tenant_session(tenant_id) as ts:
        row = await _load_config(ts, tenant_id, config_id)
        return _to_response(row)


@webhooks_router.patch(
    "/tenants/{tenant_id}/webhooks/{config_id}", response_model=WebhookConfigResponse
)
async def update_webhook_config(
    tenant_id: str, config_id: str, request: Request
) -> WebhookConfigResponse:
    """Update a webhook config (target_url re-SSRF-guarded; secrets re-encrypted on rotate).

    Only the fields present in the body change (model_fields_set). A provided
    credential / signing_secret is re-encrypted and replaces the stored ciphertext
    (rotation); omitting them leaves the stored secret untouched.
    """
    body = await parse_body(request, WebhookConfigUpdate)
    updates = body.model_fields_set
    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no_fields")

    # Re-guard a changed URL BEFORE persistence (an SSRF-unsafe URL never lands).
    if "target_url" in updates and body.target_url is not None:
        _guard_target_url(body.target_url)

    async with get_tenant_session(tenant_id) as ts:
        row = await _load_config(ts, tenant_id, config_id)

        if "target_url" in updates and body.target_url is not None:
            row.target_url = body.target_url
        if "min_severity" in updates and body.min_severity is not None:
            row.min_severity = body.min_severity
        if "enabled" in updates and body.enabled is not None:
            row.enabled = body.enabled
        # Secret rotation: re-encrypt + replace. Encrypt BEFORE storing; never log.
        if "credential" in updates:
            row.credential = encrypt(body.credential) if body.credential is not None else None
        if "signing_secret" in updates:
            row.signing_secret = (
                encrypt(body.signing_secret) if body.signing_secret is not None else None
            )
        row.updated_at = datetime.now(UTC)

        provider = row.provider
        # Response built before commit (RLS GUC clears at commit — see create_webhook_config).
        await ts.flush()
        resp = _to_response(row)
        await ts.commit()

    await _emit_config_event(
        tenant_id=tenant_id, request=request, provider=provider, config_action="updated"
    )
    return resp


@webhooks_router.delete(
    "/tenants/{tenant_id}/webhooks/{config_id}", response_model=WebhookConfigResponse
)
async def delete_webhook_config(
    tenant_id: str, config_id: str, request: Request
) -> WebhookConfigResponse:
    """Soft-delete a webhook config: set enabled=False (ADR §5.2 — no hard DELETE path).

    The table grants only SELECT/INSERT/UPDATE to sentinel_app and carries no
    deleted_at column, so disabling is the deletion semantic. The disabled config is
    skipped by the dispatcher filter; the row is retained for auditability and can be
    re-enabled. Emits config_action="deleted".
    """
    async with get_tenant_session(tenant_id) as ts:
        row = await _load_config(ts, tenant_id, config_id)
        row.enabled = False
        row.updated_at = datetime.now(UTC)
        provider = row.provider
        # Response built before commit (RLS GUC clears at commit — see create_webhook_config).
        await ts.flush()
        resp = _to_response(row)
        await ts.commit()

    await _emit_config_event(
        tenant_id=tenant_id, request=request, provider=provider, config_action="deleted"
    )
    return resp
