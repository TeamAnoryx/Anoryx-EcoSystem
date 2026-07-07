"""Inbound frame dispatch + the chat.send pipeline (R-005 core, FORK D placement).

The dispatcher maps ``msg_type`` -> async handler. R-005 registered the FOUR client->server chat
handlers (``chat.send``, ``chat.read``, ``typing.set``, ``presence.set``); R-007 adds the THREE
client->server 1-on-1 huddle/signaling handlers (``huddle.invite``, ``huddle.hangup``,
``signal.send``) to this SAME table, no rearchitecting. ``huddle.update`` / ``signal.relay`` are
SERVER->client only — a client that sends one of those (a protocol misuse, not a supported
operation) still gets ``huddle_unavailable``, never a silent drop. Any other / malformed frame is
answered with a single ``error`` frame.

THE SEND PIPELINE (FORK D — the seam is strictly BEFORE persist + fan-out):
  1. validate the frame (correlation fields, closed shape, content bound);
  2. authorize (``chat:write`` scope + LIVE DB membership);
  3. INSPECT via the seam (awaited in-line);
  4. on PASS only: persist (assign message_id + per-channel seq), ack ``accepted``, fan out
     ``chat.message``. A ``blocked`` / ``seam_unavailable`` / raising inspector yields a
     ``chat.ack`` ``blocked`` and the message is NEVER persisted and NEVER delivered (fail-closed).

THE HUDDLE SIGNALING SURFACE (R-007, ``huddle.invite``/``huddle.hangup``/``signal.send``): 1-on-1
only, user-to-user (not channel fan-out) via ``ConnectionRegistry.user_connections``, lifecycle +
busy/one-active-session-per-user tracked in the in-process ``HuddleRegistry`` (see
``realtime/huddle.py``). ``signal.send`` runs the SAME fail-closed inspection seam as chat.send
(ADR-0001 D4 — "the seam governs chat message content + signaling metadata") before relaying;
huddle MEDIA (the resulting P2P WebRTC stream) is never inspected — only the signaling payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from ..auth.errors import new_request_id
from ..persistence import chat_repo
from ..persistence.async_database import get_tenant_session
from .frames import (
    MAX_CONTENT_LEN,
    ChatReadFrame,
    HuddleHangupFrame,
    HuddleInviteFrame,
    PresenceSetFrame,
    SignalSendFrame,
    TypingSetFrame,
    build_chat_ack_accepted,
    build_chat_ack_blocked,
    build_chat_message,
    build_error,
    build_huddle_archival,
    build_huddle_update,
    build_presence_update,
    build_signal_relay,
    build_typing_update,
    signal_content,
    valid_client_msg_id,
    valid_content_type,
    valid_uuid,
)
from .authz import AuthzPrincipal, ChannelAction, authorize
from .huddle import ACTIVE_STATES, Huddle, HuddleRegistry, new_huddle_id
from .inspector import InspectionOutcome, MessageInspector
from .message import new_message_id
from .registry import Connection, ConnectionRegistry
from .resolver import TeamMembershipResolver

# The closed key set of an inbound chat.send (contracts/messages.schema.json ChatSend).
_CHAT_SEND_KEYS = {"msg_type", "client_msg_id", "channel_id", "content", "content_type"}

# Pre-parse frame size cap: reject an oversized raw frame BEFORE json.loads buffers/parses it
# (matches the REST 64 KiB body cap). content is bounded at 16 KiB; the largest legitimate frame
# (content + envelope) fits well under this, so 64 KiB is a generous DoS guard, not a functional
# limit. An oversized frame -> message_too_large (no expensive parse of attacker-sized input).
MAX_FRAME_BYTES = 65536

# SERVER->client-only catalog members (R-007). A client that sends one of these gets
# huddle_unavailable, not a silent drop — see the dispatcher docstring above.
_SIGNALING_MSG_TYPES = frozenset({"huddle.update", "signal.relay"})


@dataclass
class RuntimeContext:
    """Per-app runtime collaborators handed to every frame handler."""

    registry: ConnectionRegistry
    inspector: MessageInspector
    resolver: TeamMembershipResolver
    huddles: HuddleRegistry


# --- chat.send (the FORK D pipeline) ---------------------------------------------------


async def handle_chat_send(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    tenant_id = conn.tenant_id
    client_msg_id = data.get("client_msg_id")
    channel_id = data.get("channel_id")

    # 1a. Without valid correlation fields we cannot build a chat.ack -> identity-agnostic error.
    if not valid_client_msg_id(client_msg_id) or not valid_uuid(channel_id):
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return

    def ack_blocked(error_code: str, inspection: InspectionOutcome | None = None) -> dict:
        return build_chat_ack_blocked(
            tenant_id=tenant_id,
            client_msg_id=client_msg_id,
            channel_id=channel_id,
            error_code=error_code,
            inspection=inspection,
        )

    # 1b. Closed-shape + content checks (we now have a correlatable ack).
    content = data.get("content")
    if set(data.keys()) - _CHAT_SEND_KEYS:  # extra keys (closed schema)
        await conn.send(ack_blocked("invalid_message"))
        return
    if not isinstance(content, str) or not valid_content_type(data.get("content_type")):
        await conn.send(ack_blocked("invalid_message"))
        return
    if len(content) > MAX_CONTENT_LEN:
        await conn.send(ack_blocked("message_too_large"))
        return
    content_type = data.get("content_type") or "text"

    # 2. Authorize via the ONE channel-authz decision point (the SAME point the REST layer calls):
    #    coarse chat:write scope + LIVE per-channel role from the resolver seam, fail-closed. A
    #    non-member, a role without post rights (a guest), a missing scope, a mismatched tenant, or
    #    an unresolvable source ALL deny with a generic `unauthorized` (no existence/role oracle).
    principal = AuthzPrincipal(tenant_id=tenant_id, user_id=conn.user_id, scopes=conn.scopes)
    async with get_tenant_session(tenant_id) as session:
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        allowed = (
            channel is not None
            and (
                await authorize(
                    session,
                    principal=principal,
                    channel=channel,
                    action=ChannelAction.POST,
                    resolver=ctx.resolver,
                )
            ).allowed
        )
    if not allowed:
        await conn.send(build_error(error_code="unauthorized", request_id=new_request_id()))
        return

    # 3. INSPECTION SEAM — awaited in-line, BEFORE persist + fan-out. Fail-closed: a raising or
    #    seam_unavailable inspector becomes a BLOCK, never a silent pass.
    try:
        outcome = await ctx.inspector.inspect(
            tenant_id=tenant_id,
            channel_id=channel_id,
            sender_user_id=conn.user_id,
            content=content,
            content_type=content_type,
        )
    except Exception:  # noqa: BLE001 - any seam failure is a fail-closed BLOCK (non-negotiable #5)
        unavailable = InspectionOutcome(
            status="seam_unavailable", evaluated_at=datetime.now(timezone.utc)
        )
        await conn.send(ack_blocked("inspection_unavailable", inspection=unavailable))
        return
    if outcome.status == "blocked":
        await conn.send(ack_blocked("message_blocked", inspection=outcome))
        return
    if outcome.status != "pass":  # seam_unavailable
        await conn.send(ack_blocked("inspection_unavailable", inspection=outcome))
        return

    # 4. PASS only — persist (assign message_id + per-channel seq), then ack + fan out.
    message_id = new_message_id()
    created_at = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as session:
        # Re-authorize in the SAME transaction as the insert to close the check->persist TOCTOU: a
        # membership/role revoked DURING the (potentially slow, R-008) inspection must not let one
        # last message through. Step 2 was the early reject; this is the authoritative atomic gate,
        # routed through the SAME decision point (not a parallel inline check).
        channel = await chat_repo.load_channel(session, tenant_id=tenant_id, channel_id=channel_id)
        allowed = (
            channel is not None
            and (
                await authorize(
                    session,
                    principal=principal,
                    channel=channel,
                    action=ChannelAction.POST,
                    resolver=ctx.resolver,
                )
            ).allowed
        )
        if not allowed:
            await conn.send(build_error(error_code="unauthorized", request_id=new_request_id()))
            return
        message = await chat_repo.insert_message(
            session,
            message_id=message_id,
            tenant_id=tenant_id,
            channel_id=channel_id,
            sender_user_id=conn.user_id,
            content=content,
            content_type=content_type,
            created_at=created_at,
            inspection_evaluated_at=outcome.evaluated_at,
        )
        await session.commit()

    await conn.send(
        build_chat_ack_accepted(
            tenant_id=tenant_id,
            client_msg_id=client_msg_id,
            channel_id=channel_id,
            message_id=message_id,
        )
    )
    # Fan out to every live connection in the channel (the sender's member connections included).
    await ctx.registry.broadcast_channel(
        tenant_id=tenant_id, channel_id=channel_id, frame=build_chat_message(message)
    )


# --- chat.read (read receipt — no server fan-out frame exists; accept + no-op) ----------


async def handle_chat_read(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    # The catalog defines no server-broadcast counterpart for chat.read (a read receipt), and no
    # consumer needs read state in R-005, so a valid frame is accepted and no-op'd; an invalid one
    # gets a single error frame. Read-state persistence is deferred until a feature consumes it.
    try:
        ChatReadFrame(**data)
    except Exception:  # noqa: BLE001 - any closed-schema violation -> one error frame
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))


# --- typing.set (broadcast typing.update to the channel) -------------------------------


async def handle_typing_set(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = TypingSetFrame(**data)
    except Exception:  # noqa: BLE001
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    # Only broadcast for a channel this connection actually delivers (its membership snapshot);
    # a typing event for a channel the user is not in is silently ignored (no DB hit per keystroke).
    if frame.channel_id not in conn.channels:
        return
    await ctx.registry.broadcast_channel(
        tenant_id=conn.tenant_id,
        channel_id=frame.channel_id,
        frame=build_typing_update(
            tenant_id=conn.tenant_id,
            channel_id=frame.channel_id,
            user_id=conn.user_id,
            state=frame.state,
        ),
        exclude=conn,
    )


# --- presence.set (ephemeral; broadcast presence.update to sharing connections) --------


async def handle_presence_set(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = PresenceSetFrame(**data)
    except Exception:  # noqa: BLE001
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    conn.presence = frame.status  # ephemeral live presence (FORK E) — never persisted
    update = build_presence_update(
        tenant_id=conn.tenant_id, user_id=conn.user_id, status=frame.status
    )
    for other in ctx.registry.sharing_connections(conn):
        if other is conn:
            continue
        await other.send(update)


# --- huddle.invite (start a 1-on-1 huddle; ring the peer) ------------------------------


async def handle_huddle_invite(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = HuddleInviteFrame(**data)
    except Exception:  # noqa: BLE001 - any closed-schema violation -> one error frame
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return

    # Coarse capability gate (mirrors chat:write on chat.send). Checked before any DB/registry
    # work so an unscoped token never learns whether a peer/channel exists.
    if "huddle:initiate" not in conn.scopes:
        await conn.send(build_error(error_code="unauthorized", request_id=new_request_id()))
        return
    if frame.peer_user_id == conn.user_id:
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return

    tenant_id = conn.tenant_id
    async with get_tenant_session(tenant_id) as session:
        peer = await chat_repo.load_user(session, tenant_id=tenant_id, user_id=frame.peer_user_id)
        if peer is None:
            # Non-oracle: an out-of-tenant / nonexistent peer looks identical to any other
            # unreachable-peer case (offline, busy) below.
            await conn.send(
                build_error(error_code="huddle_unavailable", request_id=new_request_id())
            )
            return
        if frame.channel_id is not None:
            channel = await chat_repo.load_channel(
                session, tenant_id=tenant_id, channel_id=frame.channel_id
            )
            principal = AuthzPrincipal(
                tenant_id=tenant_id, user_id=conn.user_id, scopes=conn.scopes
            )
            allowed = (
                channel is not None
                and (
                    await authorize(
                        session,
                        principal=principal,
                        channel=channel,
                        action=ChannelAction.READ,
                        resolver=ctx.resolver,
                    )
                ).allowed
                and await chat_repo.is_member(
                    session,
                    tenant_id=tenant_id,
                    channel_id=frame.channel_id,
                    user_id=frame.peer_user_id,
                )
            )
            if not allowed:
                await conn.send(
                    build_error(error_code="huddle_unavailable", request_id=new_request_id())
                )
                return

    if ctx.huddles.active_huddle_id_for(tenant_id=tenant_id, user_id=conn.user_id) is not None:
        # The caller is already in a session (client bug / race) — reject rather than let one
        # user hold two concurrent huddles.
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    peer_connections = ctx.registry.user_connections(tenant_id, frame.peer_user_id)
    if not peer_connections:
        # No live socket for the peer — no offline queueing/ringing is built (lean surface).
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return
    if (
        ctx.huddles.active_huddle_id_for(tenant_id=tenant_id, user_id=frame.peer_user_id)
        is not None
    ):
        # Real "busy" (a phone-style signal to the caller only) — not an error, a lifecycle state.
        busy_id = new_huddle_id()
        now = datetime.now(timezone.utc)
        archival = build_huddle_archival(
            huddle_id=busy_id, seq=ctx.huddles.next_seq(tenant_id), created_at=now
        )
        await conn.send(
            build_huddle_update(
                huddle_id=busy_id,
                tenant_id=tenant_id,
                peer_user_id=frame.peer_user_id,
                state="busy",
                archival=archival,
            )
        )
        return

    huddle = Huddle(
        huddle_id=new_huddle_id(),
        tenant_id=tenant_id,
        inviter_user_id=conn.user_id,
        peer_user_id=frame.peer_user_id,
        channel_id=frame.channel_id,
        state="ringing",
    )
    ctx.huddles.create(huddle)

    for c in ctx.registry.user_connections(tenant_id, conn.user_id):
        await c.send(
            build_huddle_update(
                huddle_id=huddle.huddle_id,
                tenant_id=tenant_id,
                peer_user_id=huddle.peer_user_id,
                state="ringing",
            )
        )
    for c in peer_connections:
        await c.send(
            build_huddle_update(
                huddle_id=huddle.huddle_id,
                tenant_id=tenant_id,
                peer_user_id=huddle.inviter_user_id,
                state="ringing",
            )
        )


# --- huddle.hangup (end/decline the huddle) ---------------------------------------------


async def handle_huddle_hangup(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = HuddleHangupFrame(**data)
    except Exception:  # noqa: BLE001
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return

    huddle = ctx.huddles.get(frame.huddle_id)
    if (
        huddle is None
        or huddle.tenant_id != conn.tenant_id
        or not huddle.is_participant(conn.user_id)
    ):
        # Non-oracle: an unknown/foreign-tenant/not-mine huddle_id all look identical.
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    # The callee hanging up WHILE still ringing (never accepted) is a decline; every other
    # hangup (the caller cancels their own ringing invite, or either side ends an accepted/
    # active call) is an ordinary end.
    final_state = (
        "declined" if huddle.state == "ringing" and conn.user_id == huddle.peer_user_id else "ended"
    )
    other_user_id = huddle.other(conn.user_id)
    ctx.huddles.transition(huddle.huddle_id, final_state)

    now = datetime.now(timezone.utc)
    archival = build_huddle_archival(
        huddle_id=huddle.huddle_id, seq=ctx.huddles.next_seq(conn.tenant_id), created_at=now
    )
    for c in ctx.registry.user_connections(conn.tenant_id, conn.user_id):
        await c.send(
            build_huddle_update(
                huddle_id=huddle.huddle_id,
                tenant_id=conn.tenant_id,
                peer_user_id=other_user_id,
                state=final_state,
                archival=archival,
            )
        )
    for c in ctx.registry.user_connections(conn.tenant_id, other_user_id):
        await c.send(
            build_huddle_update(
                huddle_id=huddle.huddle_id,
                tenant_id=conn.tenant_id,
                peer_user_id=conn.user_id,
                state=final_state,
                archival=archival,
            )
        )


# --- signal.send (relay WebRTC offer/answer/ICE to the single peer) --------------------


async def handle_signal_send(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = SignalSendFrame(**data)
    except Exception:  # noqa: BLE001
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return

    huddle = ctx.huddles.get(frame.huddle_id)
    if (
        huddle is None
        or huddle.tenant_id != conn.tenant_id
        or not huddle.is_participant(conn.user_id)
        or huddle.state not in ACTIVE_STATES
    ):
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    # Inspection seam (ADR-0001 D4). huddle_id stands in for the seam's channel_id parameter —
    # a documented reuse of the MessageInspector shape (ADR-0007), since a huddle need not have
    # a channel of its own. Fail-closed: block/unavailable/raise all stop the relay.
    try:
        outcome = await ctx.inspector.inspect(
            tenant_id=conn.tenant_id,
            channel_id=huddle.huddle_id,
            sender_user_id=conn.user_id,
            content=signal_content(frame.signal),
            content_type="text",
        )
    except Exception:  # noqa: BLE001 - a seam failure is a fail-closed BLOCK, never a silent relay
        await conn.send(
            build_error(error_code="inspection_unavailable", request_id=new_request_id())
        )
        return
    if outcome.status == "blocked":
        await conn.send(build_error(error_code="message_blocked", request_id=new_request_id()))
        return
    if outcome.status != "pass":  # seam_unavailable
        await conn.send(
            build_error(error_code="inspection_unavailable", request_id=new_request_id())
        )
        return

    other_user_id = huddle.other(conn.user_id)
    other_connections = ctx.registry.user_connections(conn.tenant_id, other_user_id)
    signal_dict = frame.signal.model_dump(mode="json", exclude_none=True)
    relay = build_signal_relay(
        tenant_id=conn.tenant_id,
        huddle_id=huddle.huddle_id,
        from_user_id=conn.user_id,
        signal=signal_dict,
    )
    delivered = False
    for c in other_connections:
        if await c.send(relay):
            delivered = True
    if not delivered:
        # The peer has no live connection to relay to (should be rare — a clean disconnect
        # already ends the huddle; see ws.py). Fail closed with feedback rather than a silent
        # drop, and leave the huddle state untouched (no transition on an undelivered signal).
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    huddle.signaled_by.add(conn.user_id)
    new_state: str | None = None
    if huddle.state == "ringing" and conn.user_id == huddle.peer_user_id:
        new_state = "accepted"
    elif huddle.state == "accepted" and len(huddle.signaled_by) == 2:
        new_state = "active"
    if new_state is None:
        return  # no lifecycle change on this signal -> relay only, no huddle.update
    ctx.huddles.transition(huddle.huddle_id, new_state)

    for c in ctx.registry.user_connections(conn.tenant_id, conn.user_id):
        await c.send(
            build_huddle_update(
                huddle_id=huddle.huddle_id,
                tenant_id=conn.tenant_id,
                peer_user_id=other_user_id,
                state=new_state,
            )
        )
    for c in other_connections:
        await c.send(
            build_huddle_update(
                huddle_id=huddle.huddle_id,
                tenant_id=conn.tenant_id,
                peer_user_id=conn.user_id,
                state=new_state,
            )
        )


# --- the dispatch table + entry point --------------------------------------------------

# R-005 registered the chat-family inbound handlers; R-007 adds the huddle/signal ones here (the
# extension point) without touching the dispatcher itself.
CHAT_HANDLERS = {
    "chat.send": handle_chat_send,
    "chat.read": handle_chat_read,
    "typing.set": handle_typing_set,
    "presence.set": handle_presence_set,
    "huddle.invite": handle_huddle_invite,
    "huddle.hangup": handle_huddle_hangup,
    "signal.send": handle_signal_send,
}


async def dispatch_frame(conn: Connection, raw_text: str, ctx: RuntimeContext) -> None:
    """Parse one inbound text frame and route it to its handler (or answer with an error)."""
    if len(raw_text) > MAX_FRAME_BYTES:
        # Reject before parsing — never buffer/parse an attacker-sized frame (DoS guard).
        await conn.send(build_error(error_code="message_too_large", request_id=new_request_id()))
        return
    try:
        data = json.loads(raw_text)
    except (ValueError, TypeError):
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    if not isinstance(data, dict):
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    msg_type = data.get("msg_type")
    handler = CHAT_HANDLERS.get(msg_type)
    if handler is None:
        # A valid-but-unsupported huddle/signaling frame -> huddle_unavailable (R-007); anything
        # else -> invalid_message. Never a silent drop.
        code = "huddle_unavailable" if msg_type in _SIGNALING_MSG_TYPES else "invalid_message"
        await conn.send(build_error(error_code=code, request_id=new_request_id()))
        return
    await handler(conn, data, ctx)
