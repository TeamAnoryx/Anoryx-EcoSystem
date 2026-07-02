"""The minimal chat REST surface (R-005) + role-based authorization & manual team mapping (R-006).

Implements the contract-locked endpoints that operate on the entities R-005 persists, so the
WebSocket chat is human-demoable with no test-only backdoors:

  * ``POST   /v1/channels``                                 (scope ``channels:write``)
  * ``PUT    /v1/channels/{channel_id}/members/{user_id}``  (scope ``channels:admin`` + channel owner/admin)
  * ``DELETE /v1/channels/{channel_id}/members/{user_id}``  (scope ``channels:admin`` + channel owner/admin)
  * ``PUT    /v1/channels/{channel_id}/team``               (scope ``channels:admin`` + channel owner/admin) — R-006
  * ``GET    /v1/channels/{channel_id}/messages``           (scope ``chat:read`` + channel membership)

All run on the ASYNC chat engine (FORK A1) and the R-003 ``get_principal`` / ``require_scope``
auth — identity (tenant/user) is read SOLELY off the verified token, never request input, so RLS
+ the server-resolved tenant give structural tenant isolation. A resource in another tenant (or a
channel the caller is not a member of / lacks the required channel role for) is resolved as a
tenant-scoped 404 — no existence oracle.

R-006 routes the member/read/map endpoints through the ONE channel-authorization decision point
(``authz.authorize``, the same point the WS pipeline calls): scope alone no longer authorizes
channel management — the caller must hold the required per-channel ``ChannelRole`` (owner/admin to
manage members or map to a team; any member to read).

HONESTY BOUNDARY (verbatim): "R-006 implements MANUAL channel<->team mapping + a documented resolver
seam. Automatic mapping requires D-016 (Delta team data - NOT shipped) + an Orchestrator team-event
contract (NOT defined). Reserved, not built." The ``PUT .../team`` endpoint is the MANUAL writer
(sets ``source='delta_team'`` + an opaque tenant-scoped ``external_ref``); the automatic Delta-event
writer is NOT built. OUT OF SCOPE (deferred): channel list/get/patch/archive + member-list.
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
from .authz import AuthzPrincipal, ChannelAction, authorize
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


class ChannelTeamMap(BaseModel):
    """PUT team-mapping input (closed) — the opaque tenant-scoped team label to map to.

    ``external_ref`` is charset-bounded to the same ``[A-Za-z0-9._:-]{1,64}`` shape the domain
    enforces (a log-injection defense on the reserved seam). The MANUAL mapping treats it as an
    opaque label — it is never dereferenced to resolve membership.
    """

    model_config = ConfigDict(extra="forbid")
    external_ref: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,64}$", max_length=64)
    ]


def _channel_dict(channel: Channel) -> dict:
    return channel.model_dump(mode="json")


def _membership_dict(membership: Membership) -> dict:
    return membership.model_dump(mode="json")


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _authz_principal(principal: AccessTokenClaims) -> AuthzPrincipal:
    """Build the channel-authz input from the verified token (identity is token-derived only)."""
    return AuthzPrincipal(
        tenant_id=principal.tenant_id, user_id=principal.sub, scopes=principal.scope_set()
    )


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
    request: Request,
    channel_id: _ChannelIdPath,
    user_id: _UserIdPath,
    body: MembershipUpsert,
    principal: AccessTokenClaims = Depends(require_scope("channels:admin")),
) -> JSONResponse:
    """Add a member or set a member's role (idempotent upsert) via the bind_membership path.

    R-006: member management is authorized at the CHANNEL level through the single decision point —
    the caller must be an owner/admin OF THIS channel, not merely hold the ``channels:admin`` scope
    (which R-005 checked alone, letting any admin-scoped principal manage any channel). A caller who
    lacks that channel role — or a channel not visible in-tenant — resolves as 404 (no existence or
    role oracle).
    """
    tenant_id = principal.tenant_id
    now = datetime.now(timezone.utc)
    resolver = request.app.state.realtime_ctx.resolver
    async with get_tenant_session(tenant_id) as session:
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        if channel is None:
            raise AuthError(ErrorCode.NOT_FOUND)  # 404 (no existence oracle across tenants)
        decision = await authorize(
            session,
            principal=_authz_principal(principal),
            channel=channel,
            action=ChannelAction.MANAGE_MEMBERS,
            resolver=resolver,
        )
        if not decision.allowed:
            raise AuthError(ErrorCode.NOT_FOUND)  # role/tenant deny -> 404 (no oracle)
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
    """Remove a member (idempotent — 204 whether or not the membership existed).

    R-006: authorized at the CHANNEL level (owner/admin of THIS channel) through the single decision
    point, not the bare ``channels:admin`` scope. Channel not visible in-tenant, or caller lacks the
    channel role -> 404 (no oracle). Re-removing an already-absent member is still 204 (idempotent).
    """
    tenant_id = principal.tenant_id
    resolver = request.app.state.realtime_ctx.resolver
    async with get_tenant_session(tenant_id) as session:
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        if channel is None:
            raise AuthError(ErrorCode.NOT_FOUND)
        decision = await authorize(
            session,
            principal=_authz_principal(principal),
            channel=channel,
            action=ChannelAction.MANAGE_MEMBERS,
            resolver=resolver,
        )
        if not decision.allowed:
            raise AuthError(ErrorCode.NOT_FOUND)  # role/tenant deny -> 404 (no oracle)
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


@router.put("/channels/{channel_id}/team", status_code=200)
async def map_channel_team(
    request: Request,
    channel_id: _ChannelIdPath,
    body: ChannelTeamMap,
    principal: AccessTokenClaims = Depends(require_scope("channels:admin")),
) -> JSONResponse:
    """MANUAL channel<->team mapping (R-006): set ``source='delta_team'`` + ``external_ref``.

    Authorized at the CHANNEL level through the single decision point — the caller must be an
    owner/admin OF THIS channel, so a mere member cannot self-escalate a channel into a team mapping.
    A DM cannot be team-mapped (the matrix denies it). Channel not visible in-tenant, caller lacks
    the channel role, or a DM -> 404 (no oracle).

    HONESTY BOUNDARY (verbatim): "R-006 implements MANUAL channel<->team mapping + a documented
    resolver seam. Automatic mapping requires D-016 (Delta team data - NOT shipped) + an Orchestrator
    team-event contract (NOT defined). Reserved, not built." ``external_ref`` is an opaque
    tenant-scoped label; membership for the mapped channel stays admin-managed via the resolver seam.
    """
    tenant_id = principal.tenant_id
    resolver = request.app.state.realtime_ctx.resolver
    async with get_tenant_session(tenant_id) as session:
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        if channel is None:
            raise AuthError(ErrorCode.NOT_FOUND)
        decision = await authorize(
            session,
            principal=_authz_principal(principal),
            channel=channel,
            action=ChannelAction.MAP_TO_TEAM,
            resolver=resolver,
        )
        if not decision.allowed:
            raise AuthError(ErrorCode.NOT_FOUND)  # role/tenant/DM deny -> 404 (no oracle)
        updated = await chat_repo.map_channel_to_team(
            session, tenant_id=tenant_id, channel_id=channel_id, external_ref=body.external_ref
        )
        if not updated:
            # The RLS-scoped UPDATE matched no row (defensive: authorize just proved it exists
            # in-tenant in this same txn, so this is unreachable on the live path). Fail closed.
            raise AuthError(ErrorCode.NOT_FOUND)
        await session.commit()
    # Build the response from the pre-loaded channel + the new mapping fields (a Core UPDATE was
    # used, so we do not re-select a possibly-stale identity-map row); the (delta_team, external_ref)
    # pair re-validates through the Channel model's seam-consistency invariant.
    mapped = Channel(
        channel_id=channel.channel_id,
        tenant_id=channel.tenant_id,
        name=channel.name,
        type=channel.type,
        source=ChannelSource.DELTA_TEAM,
        external_ref=body.external_ref,
        created_by=channel.created_by,
        created_at=channel.created_at,
        archived=channel.archived,
    )
    return JSONResponse(status_code=200, content=_channel_dict(mapped))


@router.get("/channels/{channel_id}/messages", status_code=200)
async def list_messages(
    request: Request,
    channel_id: _ChannelIdPath,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    principal: AccessTokenClaims = Depends(require_scope("chat:read")),
) -> dict:
    """Keyset-paginated channel history (newest first), member-only. Non-member -> 404.

    R-006: the membership gate runs through the single decision point (READ action) — the SAME point
    the WS pipeline uses — so read authorization has one source of truth. Non-member / other tenant /
    no-such-channel all resolve as 404 (no existence or membership oracle).
    """
    tenant_id = principal.tenant_id
    resolver = request.app.state.realtime_ctx.resolver
    before_seq: int | None = None
    if cursor is not None:
        try:
            before_seq = int(cursor)
        except ValueError as exc:
            raise AuthError(ErrorCode.INVALID_REQUEST) from exc  # 400 (opaque-cursor decode)
    async with get_tenant_session(tenant_id) as session:
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        allowed = (
            channel is not None
            and (
                await authorize(
                    session,
                    principal=_authz_principal(principal),
                    channel=channel,
                    action=ChannelAction.READ,
                    resolver=resolver,
                )
            ).allowed
        )
        if not allowed:
            raise AuthError(ErrorCode.NOT_FOUND)  # member-only; no existence/membership oracle
        messages = await chat_repo.load_message_history(
            session,
            tenant_id=tenant_id,
            channel_id=channel_id,
            limit=limit,
            before_seq=before_seq,
        )
    next_cursor = str(messages[-1].seq) if len(messages) == limit else None
    return {"messages": [to_message_record(m) for m in messages], "next_cursor": next_cursor}
