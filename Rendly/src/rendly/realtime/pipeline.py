"""Inbound frame dispatch + the chat.send pipeline (R-005 core, FORK D placement).

The dispatcher maps ``msg_type`` -> async handler. R-005 registers the FOUR client->server chat
handlers (``chat.send``, ``chat.read``, ``typing.set``, ``presence.set``); the 1-on-1
huddle/signaling handlers are R-007 and ADD to this same table with no rearchitecting (a
``huddle.*`` / ``signal.*`` frame received in R-005 is answered ``huddle_unavailable``, not
silently dropped). Any other / malformed frame is answered with a single ``error`` frame.

THE SEND PIPELINE (FORK D — the seam is strictly BEFORE persist + fan-out):
  1. validate the frame (correlation fields, closed shape, content bound);
  2. authorize (``chat:write`` scope + LIVE DB membership);
  3. INSPECT via the seam (awaited in-line);
  4. on PASS only: persist (assign message_id + per-channel seq), ack ``accepted``, fan out
     ``chat.message``. A ``blocked`` / ``seam_unavailable`` / raising inspector yields a
     ``chat.ack`` ``blocked`` and the message is NEVER persisted and NEVER delivered (fail-closed).
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
    PresenceSetFrame,
    TypingSetFrame,
    build_chat_ack_accepted,
    build_chat_ack_blocked,
    build_chat_message,
    build_error,
    build_presence_update,
    build_typing_update,
    valid_client_msg_id,
    valid_content_type,
    valid_uuid,
)
from .inspector import InspectionOutcome, MessageInspector
from .message import new_message_id
from .registry import Connection, ConnectionRegistry

# The closed key set of an inbound chat.send (contracts/messages.schema.json ChatSend).
_CHAT_SEND_KEYS = {"msg_type", "client_msg_id", "channel_id", "content", "content_type"}

# Pre-parse frame size cap: reject an oversized raw frame BEFORE json.loads buffers/parses it
# (matches the REST 64 KiB body cap). content is bounded at 16 KiB; the largest legitimate frame
# (content + envelope) fits well under this, so 64 KiB is a generous DoS guard, not a functional
# limit. An oversized frame -> message_too_large (no expensive parse of attacker-sized input).
MAX_FRAME_BYTES = 65536

# Catalog frames that belong to the 1-on-1 huddle/signaling surface (R-007). Received in R-005
# they are a valid-but-unsupported frame -> huddle_unavailable (never a silent drop).
_SIGNALING_MSG_TYPES = frozenset(
    {"huddle.invite", "huddle.update", "huddle.hangup", "signal.send", "signal.relay"}
)


@dataclass
class RuntimeContext:
    """Per-app runtime collaborators handed to every frame handler."""

    registry: ConnectionRegistry
    inspector: MessageInspector


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

    # 2. Authorize: per-frame chat:write scope + LIVE DB membership (never a cached set).
    if "chat:write" not in conn.scopes:
        await conn.send(build_error(error_code="unauthorized", request_id=new_request_id()))
        return
    async with get_tenant_session(tenant_id) as session:
        member = await chat_repo.is_member(
            session, tenant_id=tenant_id, channel_id=channel_id, user_id=conn.user_id
        )
    if not member:
        # Not a member (or no such channel in-tenant): unauthorized, with no existence oracle.
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
        # Re-check membership in the SAME transaction as the insert to close the check->persist
        # TOCTOU: a membership revoked DURING the (potentially slow, R-008) inspection must not let
        # one last message through. The pre-inspection check above is the early authz reject; this
        # is the authoritative atomic gate.
        if not await chat_repo.is_member(
            session, tenant_id=tenant_id, channel_id=channel_id, user_id=conn.user_id
        ):
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


# --- the dispatch table + entry point --------------------------------------------------

# R-005 registers ONLY the chat-family inbound handlers. R-007 adds huddle.invite / huddle.hangup
# / signal.send here (the extension point) without touching the dispatcher.
CHAT_HANDLERS = {
    "chat.send": handle_chat_send,
    "chat.read": handle_chat_read,
    "typing.set": handle_typing_set,
    "presence.set": handle_presence_set,
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
