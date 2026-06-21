"""Admin virtual-key management routes (F-012a, ADR-0014 §5).

Mint / list / rotate / revoke virtual keys for a target tenant. Key operations
run inside get_tenant_session(TARGET) so RLS scopes every write/read to the named
tenant (one tenant per request). The plaintext secret is generated server-side
and returned EXACTLY ONCE (mint/rotate); only the HMAC fingerprint is stored, and
list returns metadata only (R4). Rotation is immediate-revoke.

Audit events are appended on a SEPARATE privileged session (append() reads the
global chain tip and requires the privileged role), after the key op commits:
  - mint   -> admin_key_minted
  - rotate -> admin_key_revoked (old) + admin_key_minted (new)
  - revoke -> admin_key_revoked
  - list   -> admin_audit_accessed (operator cross-tenant data read, R1/vector 14)
Key events carry the key's REAL team_id/project_id (D7).
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from admin.audit import emit_admin_event
from admin.schemas import KeyListResponse, KeyMintRequest, KeyMintResponse, KeyResponse
from admin.scope import enforce_admin_scope
from admin.util import actor_id, parse_body, request_id, validate_tenant_id_path
from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.virtual_api_key_repository import (
    VirtualApiKeyNotFoundError,
    VirtualApiKeyRepository,
)

# Router deps run after the parent admin_router's require_admin: validate the path
# tenant_id, then enforce the operator's tenant-pin + role (ADR-0017 §3 D2, R1).
keys_router = APIRouter(
    tags=["admin"],
    dependencies=[Depends(validate_tenant_id_path), Depends(enforce_admin_scope)],
)


async def _assert_scope_in_tenant(
    ts: AsyncSession, tenant_id: str, team_id: str, project_id: str
) -> None:
    """Verify team_id + project_id belong to the target tenant (security-audit HIGH).

    Runs on the RLS-scoped tenant session, so a team/project from another tenant
    returns zero rows. FK referential checks bypass RLS in Postgres, so this
    application-level check is the real cross-tenant binding guard (ADR-0014 §5):
    without it an operator could mint a key for tenant A bound to tenant B's
    team/project, corrupting cross-tenant attribution. 422 on mismatch.
    """
    team = (
        await ts.execute(
            text("SELECT 1 FROM teams WHERE team_id = :tm AND tenant_id = :t"),
            {"tm": team_id, "t": tenant_id},
        )
    ).first()
    if team is None:
        raise HTTPException(status_code=422, detail="team_not_in_tenant")
    proj = (
        await ts.execute(
            text(
                "SELECT 1 FROM projects "
                "WHERE project_id = :p AND team_id = :tm AND tenant_id = :t"
            ),
            {"p": project_id, "tm": team_id, "t": tenant_id},
        )
    ).first()
    if proj is None:
        raise HTTPException(status_code=422, detail="project_not_in_tenant")


# Plaintext key prefix (matches the existing virtual-key convention used in tests).
_KEY_PREFIX = "sk-sentinel-"


def _new_plaintext() -> str:
    """Generate a fresh, high-entropy plaintext virtual key (returned once)."""
    return _KEY_PREFIX + secrets.token_urlsafe(32)


@keys_router.post(
    "/tenants/{tenant_id}/keys",
    response_model=KeyMintResponse,
    status_code=status.HTTP_201_CREATED,
)
async def mint_key(tenant_id: str, request: Request) -> KeyMintResponse:
    """Mint a virtual key for the target tenant. Returns the secret ONCE."""
    body = await parse_body(request, KeyMintRequest)
    rid = request_id(request)
    aid = actor_id(request)
    plaintext = _new_plaintext()

    # get_tenant_session autobegins a transaction (the set_config GUC call), so the
    # caller must NOT open another with ts.begin(); commit explicitly to persist.
    async with get_tenant_session(tenant_id) as ts:
        # HIGH fix: team/project must belong to the target tenant (RLS-scoped check).
        await _assert_scope_in_tenant(ts, tenant_id, body.team_id, body.project_id)
        row = await VirtualApiKeyRepository(ts).create(
            plaintext,
            tenant_id=tenant_id,
            team_id=body.team_id,
            project_id=body.project_id,
            agent_id=body.agent_id,
            label=body.label,
            expires_at=body.expires_at,
        )
        await ts.refresh(row)
        meta = KeyResponse.model_validate(row)
        await ts.commit()

    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_key_minted",
                target_tenant_id=tenant_id,
                request_id=rid,
                team_id=body.team_id,
                project_id=body.project_id,
                actor_id=aid,
            )
    return KeyMintResponse(secret=plaintext, key=meta)


@keys_router.get("/tenants/{tenant_id}/keys", response_model=KeyListResponse)
async def list_keys(tenant_id: str, request: Request) -> KeyListResponse:
    """List key METADATA for the target tenant (never secrets). Audited (R1)."""
    rid = request_id(request)
    aid = actor_id(request)
    async with get_tenant_session(tenant_id) as ts:
        rows = await VirtualApiKeyRepository(ts).list_for_tenant(tenant_id)
        keys = [KeyResponse.model_validate(r) for r in rows]

    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_audit_accessed",
                target_tenant_id=tenant_id,
                request_id=rid,
                actor_id=aid,
            )
    return KeyListResponse(keys=keys, count=len(keys))


@keys_router.post(
    "/tenants/{tenant_id}/keys/{key_id}/rotate",
    response_model=KeyMintResponse,
    status_code=status.HTTP_201_CREATED,
)
async def rotate_key(tenant_id: str, key_id: str, request: Request) -> KeyMintResponse:
    """Rotate a key: immediate-revoke old + mint new. Returns the new secret ONCE."""
    rid = request_id(request)
    aid = actor_id(request)
    plaintext = _new_plaintext()
    async with get_tenant_session(tenant_id) as ts:
        try:
            new = await VirtualApiKeyRepository(ts).rotate(
                key_id, plaintext, caller_tenant_id=tenant_id
            )
        except VirtualApiKeyNotFoundError:
            raise HTTPException(status_code=404, detail="key_not_found") from None
        await ts.refresh(new)
        meta = KeyResponse.model_validate(new)
        team_id, project_id = new.team_id, new.project_id
        await ts.commit()

    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_key_revoked",
                target_tenant_id=tenant_id,
                request_id=rid,
                team_id=team_id,
                project_id=project_id,
                actor_id=aid,
            )
            await emit_admin_event(
                ps,
                event_type="admin_key_minted",
                target_tenant_id=tenant_id,
                request_id=rid,
                team_id=team_id,
                project_id=project_id,
                actor_id=aid,
            )
    return KeyMintResponse(secret=plaintext, key=meta)


@keys_router.post(
    "/tenants/{tenant_id}/keys/{key_id}/revoke",
    response_model=KeyResponse,
)
async def revoke_key(tenant_id: str, key_id: str, request: Request) -> KeyResponse:
    """Revoke (deactivate) a key. The gateway denies it on the next request."""
    rid = request_id(request)
    aid = actor_id(request)
    async with get_tenant_session(tenant_id) as ts:
        try:
            row = await VirtualApiKeyRepository(ts).deactivate(key_id, caller_tenant_id=tenant_id)
        except VirtualApiKeyNotFoundError:
            raise HTTPException(status_code=404, detail="key_not_found") from None
        await ts.refresh(row)
        meta = KeyResponse.model_validate(row)
        team_id, project_id = row.team_id, row.project_id
        await ts.commit()

    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_admin_event(
                ps,
                event_type="admin_key_revoked",
                target_tenant_id=tenant_id,
                request_id=rid,
                team_id=team_id,
                project_id=project_id,
                actor_id=aid,
            )
    return meta
