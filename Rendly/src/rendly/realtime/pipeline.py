"""Inbound frame dispatch + the chat.send pipeline (R-005 core, FORK D placement).

The dispatcher maps ``msg_type`` -> async handler. R-005 registered the FOUR client->server chat
handlers (``chat.send``, ``chat.read``, ``typing.set``, ``presence.set``); R-007 ADDS the three
1-on-1 huddle/signaling handlers (``huddle.invite``, ``huddle.hangup``, ``signal.send``) to this
SAME table, exactly the extension point ADR-0005 built for it — no rearchitecting. Any other /
malformed frame is answered with a single ``error`` frame.

THE SEND PIPELINE (FORK D — the seam is strictly BEFORE persist + fan-out):
  1. validate the frame (correlation fields, closed shape, content bound);
  2. authorize (``chat:write`` scope + LIVE DB membership);
  3. INSPECT via the seam (awaited in-line);
  4. on PASS only: persist (assign message_id + per-channel seq, with the R-008 per-category
     ``detectors`` findings), ack ``accepted``, fan out ``chat.message``. A ``blocked`` /
     ``seam_unavailable`` / raising inspector yields a ``chat.ack`` ``blocked`` and the message is
     NEVER persisted and NEVER delivered (fail-closed) — R-008 additionally records the rejection
     in ``inspection_audit_log`` (``_record_inspection_audit``), the administrative-oversight
     trail for a send that ``messages`` structurally cannot show (ADR-0008).

THE HUDDLE/SIGNALING SURFACE (R-007, ADR-0007): LIVE state is ephemeral, single-instance, NOT
persisted (see ``realtime/huddle.py``). ``huddle:initiate`` gates STARTING a huddle
(``huddle.invite``) and fetching ICE config; a caller who is not that huddle's participant is
denied continuing it (``signal.send`` / ``huddle.hangup``) via
``HuddleManager.get(...).peer_of(...)`` — no separate scope check, because holding a valid
``huddle_id`` the manager recognizes for THIS user already proves participation (it was minted
server-side and handed only to the two peers). huddle MEDIA never rides this pipeline — only
signaling metadata (SDP/ICE) does, and it is never content-inspected (R-001 D4 honesty
boundary). R-009: the terminal ``ended`` transition (``handle_huddle_hangup`` below, and the
disconnect-triggered end in ``realtime/ws.py``) additionally persists a hash-chained session
record via ``archive_ended_huddle_best_effort`` — best-effort, never blocking the broadcast.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from ..auth.errors import new_request_id
from ..persistence import chat_repo, huddle_repo
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
    build_huddle_update,
    build_presence_update,
    build_signal_relay,
    build_typing_update,
    valid_client_msg_id,
    valid_content_type,
    valid_uuid,
)
from .authz import AuthzPrincipal, ChannelAction, authorize
from .huddle import Huddle, HuddleArchive, HuddleManager, HuddleState, new_huddle_id
from .ice import IceCredentialProvider
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


@dataclass
class RuntimeContext:
    """Per-app runtime collaborators handed to every frame handler.

    ``ice_provider`` is consumed only by the REST ``GET /huddles/ice-servers`` route
    (``realtime/rest.py``), not by this module's frame handlers, but it lives here alongside
    ``huddles`` so the app assembler (``realtime/app.py``) has ONE runtime-context object to wire.
    """

    registry: ConnectionRegistry
    inspector: MessageInspector
    resolver: TeamMembershipResolver
    huddles: HuddleManager
    ice_provider: IceCredentialProvider


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
        await _record_inspection_audit(
            tenant_id=tenant_id,
            channel_id=channel_id,
            sender_user_id=conn.user_id,
            outcome=unavailable,
        )
        await conn.send(ack_blocked("inspection_unavailable", inspection=unavailable))
        return
    if outcome.status == "blocked":
        await _record_inspection_audit(
            tenant_id=tenant_id,
            channel_id=channel_id,
            sender_user_id=conn.user_id,
            outcome=outcome,
        )
        await conn.send(ack_blocked("message_blocked", inspection=outcome))
        return
    if outcome.status != "pass":  # seam_unavailable
        await _record_inspection_audit(
            tenant_id=tenant_id,
            channel_id=channel_id,
            sender_user_id=conn.user_id,
            outcome=outcome,
        )
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
            detectors=outcome.detectors,
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


async def _record_inspection_audit(
    *, tenant_id: str, channel_id: str, sender_user_id: str, outcome: InspectionOutcome
) -> None:
    """Record a BLOCKED / SEAM-UNAVAILABLE inspection outcome (R-008 administrative oversight).

    The ONLY durable trace of a rejected send — ``messages`` never sees it (fail-closed
    pre-persist). Metadata only (tenant/channel/sender/status/detectors), never the message
    content, which this function is never even passed. Best-effort: a failure to WRITE the audit
    row must not change the ack the sender already fail-closed on (the send is blocked either
    way), so this never raises into the caller.
    """
    try:
        async with get_tenant_session(tenant_id) as session:
            await chat_repo.insert_inspection_audit(
                session,
                audit_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                channel_id=channel_id,
                sender_user_id=sender_user_id,
                status=outcome.status,
                detectors=outcome.detectors,
                evaluated_at=outcome.evaluated_at,
                created_at=datetime.now(timezone.utc),
            )
            await session.commit()
    except Exception:  # noqa: BLE001 - the send is ALREADY blocked; an audit-write failure must
        # not surface as a different error to the sender, and must never flip the outcome to a
        # pass. Silent here as a matter of ack-stability, not a hidden fail-open.
        pass


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


# --- huddle.invite (start a 1-on-1 huddle; ringing/busy fan-out) -----------------------


async def handle_huddle_invite(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = HuddleInviteFrame(**data)
    except Exception:  # noqa: BLE001 - any closed-schema violation -> one error frame
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    # huddle:initiate gates STARTING a huddle (matches contracts/openapi.yaml's scope
    # description); continuing an existing one (signal.send/huddle.hangup) is gated by
    # participation, not this scope.
    if "huddle:initiate" not in conn.scopes:
        await conn.send(build_error(error_code="unauthorized", request_id=new_request_id()))
        return
    tenant_id = conn.tenant_id
    peer_user_id = frame.peer_user_id
    if peer_user_id == conn.user_id:
        # Structurally 1-on-1 with exactly one OTHER peer — self-invite is a malformed request.
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return

    peer_conns = ctx.registry.user_connections(tenant_id, peer_user_id)
    if not peer_conns:
        # No live connection for this (tenant, user) -> cannot ring them. Fail-closed and
        # non-oracle: this is indistinguishable from "peer_user_id does not exist in this
        # tenant" (no separate DB lookup is made), matching the REST 404 no-existence-oracle
        # posture elsewhere in R-006.
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    if ctx.huddles.active_huddle_id(tenant_id, conn.user_id) is not None or (
        ctx.huddles.active_huddle_id(tenant_id, peer_user_id) is not None
    ):
        # Ordinary phone-call semantics: you can't place, or be placed into, a second call
        # while already ringing/accepted/active in one. Feedback is CALLER-ONLY (a throwaway
        # huddle_id — nothing is registered) — the busy party is never notified of the attempt.
        await conn.send(
            build_huddle_update(
                huddle_id=new_huddle_id(),
                tenant_id=tenant_id,
                peer_user_id=peer_user_id,
                state=HuddleState.BUSY.value,
            )
        )
        return

    huddle = ctx.huddles.start(
        tenant_id=tenant_id,
        caller_id=conn.user_id,
        callee_id=peer_user_id,
        now=datetime.now(timezone.utc),
    )
    await _broadcast_huddle_update(ctx, huddle, HuddleState.RINGING)


# --- signal.send (relay WebRTC offer/answer/ICE to the single peer; infer accept/active) -


async def handle_signal_send(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = SignalSendFrame(**data)
    except Exception:  # noqa: BLE001
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    huddle, peer_id = _authorized_huddle(ctx, conn, frame.huddle_id)
    if huddle is None or peer_id is None:
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    # Relay FIRST (the direct effect of this frame), THEN announce any state transition — so the
    # peer's SDP/ICE payload is never held up behind the (equally informative but secondary)
    # huddle.update broadcast.
    relay = build_signal_relay(
        tenant_id=conn.tenant_id,
        huddle_id=huddle.huddle_id,
        from_user_id=conn.user_id,
        signal=frame.signal,
    )
    for peer_conn in ctx.registry.user_connections(conn.tenant_id, peer_id):
        await peer_conn.send(relay)

    # Signaling-liveness heuristic (see realtime/huddle.py honesty boundary): the CALLEE's first
    # signal after `ringing` is treated as their accept; the CALLER's first signal after
    # `accepted` is treated as the session going active. Neither observes real ICE/DTLS state.
    if huddle.state is HuddleState.RINGING and conn.user_id == huddle.callee_id:
        ctx.huddles.transition(huddle, HuddleState.ACCEPTED)
        await _broadcast_huddle_update(ctx, huddle, HuddleState.ACCEPTED)
    elif huddle.state is HuddleState.ACCEPTED and conn.user_id == huddle.caller_id:
        ctx.huddles.transition(huddle, HuddleState.ACTIVE)
        await _broadcast_huddle_update(ctx, huddle, HuddleState.ACTIVE)


# --- huddle.hangup (end or decline the huddle; terminal, releases it from the manager) -


async def handle_huddle_hangup(conn: Connection, data: dict, ctx: RuntimeContext) -> None:
    try:
        frame = HuddleHangupFrame(**data)
    except Exception:  # noqa: BLE001
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    huddle, peer_id = _authorized_huddle(ctx, conn, frame.huddle_id)
    if huddle is None or peer_id is None:
        await conn.send(build_error(error_code="huddle_unavailable", request_id=new_request_id()))
        return

    # The callee hanging up a still-ringing invite is a DECLINE; every other hangup (the caller
    # retracting a ring, or either side leaving an accepted/active session) is an END.
    if huddle.state is HuddleState.RINGING and conn.user_id == huddle.callee_id:
        end_state = HuddleState.DECLINED
    else:
        end_state = HuddleState.ENDED
    archive = None
    if end_state is HuddleState.ENDED:
        archive = await archive_ended_huddle_best_effort(
            huddle, ended_at=datetime.now(timezone.utc)
        )
    ctx.huddles.transition(huddle, end_state)
    await _broadcast_huddle_update(ctx, huddle, end_state, archive=archive)


# --- huddle helpers ----------------------------------------------------------------------


async def archive_ended_huddle_best_effort(
    huddle: Huddle, *, ended_at: datetime
) -> HuddleArchive | None:
    """Persist the R-009 session record for an ENDED huddle. Best-effort: never raises.

    Called from the ONE place a huddle transitions to ``ended`` on the live path
    (``handle_huddle_hangup`` above) AND from ``ws.py``'s disconnect-triggered end — mirrors
    ``_record_inspection_audit``'s posture: the huddle has ALREADY ended from the two peers'
    perspective (signaling/media already stopped) by the time this runs, so a DB failure here
    must not block or alter the ``ended`` broadcast. A failure degrades to no ``archival`` field
    on that broadcast (``build_huddle_update``) rather than losing the ``ended`` notice itself.

    NOT itself shielded from cancellation — the disconnect-triggered caller
    (``realtime/ws.py``) wraps its ENTIRE ended-huddle notification (this call AND the
    subsequent peer send) in ``anyio.CancelScope(shield=True)``; see that module for why. The
    hangup-triggered caller runs in an uncancelled context and needs no shield either way.
    """
    try:
        async with get_tenant_session(huddle.tenant_id) as session:
            archive = await huddle_repo.archive_ended_huddle(
                session,
                tenant_id=huddle.tenant_id,
                huddle_id=huddle.huddle_id,
                caller_id=huddle.caller_id,
                callee_id=huddle.callee_id,
                created_at=huddle.created_at,
                ended_at=ended_at,
            )
            await session.commit()
            return archive
    except Exception:  # noqa: BLE001 - best-effort archiving; never blocks the ended broadcast
        return None


def _authorized_huddle(
    ctx: RuntimeContext, conn: Connection, huddle_id: str
) -> tuple[Huddle | None, str | None]:
    """Resolve ``huddle_id`` for this connection's tenant + confirm it is a live participant.

    Holding a ``huddle_id`` the manager recognizes for THIS (tenant, user) pair is itself the
    authorization — huddle ids are server-minted and handed only to the two peers (``start`` /
    the ringing fan-out), so there is no separate scope check here (mirrors the channel-authz
    seam's fail-closed "not a participant -> deny", but the "membership" is the manager's live
    state, not a DB row). A terminal huddle is already released from the manager, so re-acting on
    it (e.g. a duplicate hangup) resolves the same as an unknown id — idempotently non-oracle.
    """
    huddle = ctx.huddles.get(conn.tenant_id, huddle_id)
    if huddle is None:
        return None, None
    peer_id = huddle.peer_of(conn.user_id)
    if peer_id is None:
        return None, None
    return huddle, peer_id


async def _broadcast_huddle_update(
    ctx: RuntimeContext, huddle: Huddle, state: HuddleState, *, archive: HuddleArchive | None = None
) -> None:
    """Send huddle.update to EVERY live connection of BOTH participants.

    ``peer_user_id`` on each recipient's frame is relative to THAT recipient (mirrors
    ``typing.update``/``presence.update`` — the field always identifies "the other party"), so
    the caller's own sockets and the callee's own sockets converge on the same session state.
    """
    for user_id, peer_id in (
        (huddle.caller_id, huddle.callee_id),
        (huddle.callee_id, huddle.caller_id),
    ):
        frame = build_huddle_update(
            huddle_id=huddle.huddle_id,
            tenant_id=huddle.tenant_id,
            peer_user_id=peer_id,
            state=state.value,
            archive=archive,
        )
        for conn in ctx.registry.user_connections(huddle.tenant_id, user_id):
            await conn.send(frame)


# --- the dispatch table + entry point --------------------------------------------------

# R-005 registered the chat-family inbound handlers; R-007 adds the huddle/signaling family here
# (the extension point ADR-0005 built for it) with no change to the dispatcher below.
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
        # server->client-only frame types (huddle.update, signal.relay, session.welcome, etc.)
        # and anything unrecognized both land here -> invalid_message. Never a silent drop.
        await conn.send(build_error(error_code="invalid_message", request_id=new_request_id()))
        return
    await handler(conn, data, ctx)
