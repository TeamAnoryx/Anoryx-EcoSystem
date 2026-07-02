"""The minimal chat REST surface (R-005) — history + channel/member management.

Implements the contract-locked endpoints that operate on the entities R-005 persists, so the
WebSocket chat is human-demoable with no test-only backdoors:

  * ``POST   /v1/channels``                          (scope ``channels:write``)
  * ``PUT    /v1/channels/{channel_id}/members/{user_id}``  (scope ``channels:admin``)
  * ``DELETE /v1/channels/{channel_id}/members/{user_id}``  (scope ``channels:admin``)
  * ``GET    /v1/channels/{channel_id}/messages``    (scope ``chat:read``)

All run on the ASYNC chat engine (FORK A1) and the R-003 ``get_principal`` / ``require_scope``
auth — identity (tenant/user) is read SOLELY off the verified token, never request input, so RLS
+ the server-resolved tenant give structural tenant isolation. A resource in another tenant (or a
channel the caller is not a member of) is resolved as a tenant-scoped 404 — no existence oracle.

OUT OF SCOPE (deferred): channel list/get/patch/archive + member-list, and the Delta-team
auto-mapping (R-006). ``source``/``external_ref`` persist nullable; no mapping logic is built.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StringConstraints

from ..auth.claims import AccessTokenClaims
from ..auth.dependencies import require_scope
from ..auth.errors import AuthError, ErrorCode
from ..channel import Channel
from ..enums import ChannelRole, ChannelSource, ChannelType
from ..membership import Membership, bind_membership
from ..persistence import chat_repo
from ..persistence.async_database import get_tenant_session
from .frames import to_message_record

_UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
_ChannelIdPath = Annotated[str, Path(pattern=_UUID_PATTERN, max_length=64)]
_UserIdPath = Annotated[str, Path(pattern=_UUID_PATTERN, max_length=64)]


class ChannelCreate(BaseModel):
    """POST /channels input (closed) — only ``manual`` channels; source/external_ref are
    server-managed and NOT client-settable, so a client-supplied one is rejected 400."""

    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    type: Literal["public", "private", "dm"]


class MembershipUpsert(BaseModel):
    """PUT member input (closed) — the RBAC role to set."""

    model_config = ConfigDict(extra="forbid")
    role: Literal["owner", "admin", "member", "guest"]


def _channel_dict(channel: Channel) -> dict:
    return channel.model_dump(mode="json")


def _membership_dict(membership: Membership) -> dict:
    return membership.model_dump(mode="json")


def _new_uuid() -> str:
    return str(uuid.uuid4())


router = APIRouter(prefix="/v1")


@router.post("/channels", status_code=201)
async def create_channel(
    body: ChannelCreate,
    principal: AccessTokenClaims = Depends(require_scope("channels:write")),
) -> JSONResponse:
    """Create a ``manual`` channel; the creator becomes its ``owner`` member (one transaction)."""
    tenant_id = principal.tenant_id
    creator_id = principal.sub
    now = datetime.now(timezone.utc)
    channel = Channel(
        channel_id=_new_uuid(),
        tenant_id=tenant_id,
        name=body.name,
        type=ChannelType(body.type),
        source=ChannelSource.MANUAL,
        external_ref=None,
        created_by=creator_id,
        created_at=now,
        archived=False,
    )
    async with get_tenant_session(tenant_id) as session:
        await chat_repo.insert_channel(session, channel)
        await session.flush()
        creator = await chat_repo.load_user(session, tenant_id=tenant_id, user_id=creator_id)
        if creator is None:
            # The token verified but its principal no longer resolves in-tenant.
            raise AuthError(ErrorCode.INVALID_TOKEN)
        owner = bind_membership(creator, channel, role=ChannelRole.OWNER, added_at=now)
        await chat_repo.insert_membership(session, owner)
        await session.commit()
    return JSONResponse(status_code=201, content=_channel_dict(channel))


@router.put("/channels/{channel_id}/members/{user_id}", status_code=200)
async def upsert_member(
    channel_id: _ChannelIdPath,
    user_id: _UserIdPath,
    body: MembershipUpsert,
    principal: AccessTokenClaims = Depends(require_scope("channels:admin")),
) -> JSONResponse:
    """Add a member or set a member's role (idempotent upsert) via the bind_membership path."""
    tenant_id = principal.tenant_id
    now = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as session:
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        if channel is None:
            raise AuthError(ErrorCode.NOT_FOUND)  # 404 (no existence oracle across tenants)
        target = await chat_repo.load_user(session, tenant_id=tenant_id, user_id=user_id)
        if target is None:
            raise AuthError(ErrorCode.NOT_FOUND)  # user not in this tenant
        # bind_membership runs the cross-tenant guard on a REAL User+Channel (both this tenant by
        # construction here); the composite FK + RLS are the next two layers.
        membership = bind_membership(target, channel, role=ChannelRole(body.role), added_at=now)
        # Idempotent upsert: memberships grant is SELECT/INSERT/DELETE (no UPDATE), so a role
        # change is delete-then-insert. delete is a no-op when absent.
        await chat_repo.delete_membership(
            session, tenant_id=tenant_id, channel_id=channel_id, user_id=user_id
        )
        await chat_repo.insert_membership(session, membership)
        await session.commit()
    return JSONResponse(status_code=200, content=_membership_dict(membership))


@router.delete("/channels/{channel_id}/members/{user_id}", status_code=204)
async def remove_member(
    request: Request,
    channel_id: _ChannelIdPath,
    user_id: _UserIdPath,
    principal: AccessTokenClaims = Depends(require_scope("channels:admin")),
) -> Response:
    """Remove a member (idempotent — 204 whether or not the membership existed)."""
    tenant_id = principal.tenant_id
    async with get_tenant_session(tenant_id) as session:
        await chat_repo.delete_membership(
            session, tenant_id=tenant_id, channel_id=channel_id, user_id=user_id
        )
        await session.commit()
    # Evict the removed member's live socket(s) from the channel so they stop receiving its
    # fan-out immediately — without this, an open socket keeps reading new messages until the
    # client reconnects (single-instance; see ConnectionRegistry.remove_user_from_channel).
    request.app.state.realtime_ctx.registry.remove_user_from_channel(
        tenant_id=tenant_id, channel_id=channel_id, user_id=user_id
    )
    return Response(status_code=204)


@router.get("/channels/{channel_id}/messages", status_code=200)
async def list_messages(
    channel_id: _ChannelIdPath,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    principal: AccessTokenClaims = Depends(require_scope("chat:read")),
) -> dict:
    """Keyset-paginated channel history (newest first), member-only. Non-member -> 404."""
    tenant_id = principal.tenant_id
    before_seq: int | None = None
    if cursor is not None:
        try:
            before_seq = int(cursor)
        except ValueError as exc:
            raise AuthError(ErrorCode.INVALID_REQUEST) from exc  # 400 (opaque-cursor decode)
    async with get_tenant_session(tenant_id) as session:
        # Member-only read: a non-member (or another tenant) is resolved as a 404 — the same
        # response as a non-existent channel, so neither existence nor membership leaks.
        member = await chat_repo.is_member(
            session, tenant_id=tenant_id, channel_id=channel_id, user_id=principal.sub
        )
        if not member:
            raise AuthError(ErrorCode.NOT_FOUND)
        messages = await chat_repo.load_message_history(
            session,
            tenant_id=tenant_id,
            channel_id=channel_id,
            limit=limit,
            before_seq=before_seq,
        )
    next_cursor = str(messages[-1].seq) if len(messages) == limit else None
    return {"messages": [to_message_record(m) for m in messages], "next_cursor": next_cursor}
