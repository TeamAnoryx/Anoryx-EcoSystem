"""The ``GET /v1/realtime`` WebSocket endpoint — handshake auth + connection lifecycle (R-005).

HANDSHAKE AUTH (R-001 LOCKED): the access token is presented EITHER as ``Authorization: Bearer
<jwt>`` OR as the ``Sec-WebSocket-Protocol`` subprotocol value ``rendly.bearer.<jwt>``. There is
NO query-string / cookie transport — a token in the URL would leak into proxy/access logs, so it
is never read from there. The subprotocol value is treated as a SECRET: it is never logged, and
the accept response acknowledges NO subprotocol (the bearer is never echoed back into the
handshake response headers). Verification is pure crypto (``rendly.auth.verify`` — no DB), so the
handshake authenticates synchronously. A missing/invalid/expired token fails the handshake (the
socket is closed before accept — no session is opened). The handshake gate is ``chat:read``;
``chat:write`` is enforced PER-FRAME at send time, so a read-only token may open the socket.
"""

from __future__ import annotations

from datetime import datetime, timezone

import anyio
from starlette.websockets import WebSocket

from ..auth.errors import new_request_id
from ..auth.tokens import TokenVerificationError, verify
from ..persistence import chat_repo
from ..persistence.async_database import get_tenant_session
from .frames import build_error, build_huddle_update, build_presence_update, build_session_welcome
from .huddle import HuddleState
from .pipeline import RuntimeContext, archive_ended_huddle_best_effort, dispatch_frame
from .registry import Connection

_BEARER_PREFIX = "Bearer "
_SUBPROTOCOL_PREFIX = "rendly.bearer."
# WS close code for a rejected handshake (policy violation) — the WS-native "401, no socket".
_CLOSE_POLICY_VIOLATION = 1008


def _extract_token(websocket: WebSocket) -> str | None:
    """Pull the access token from the Authorization header OR the bearer subprotocol.

    NEVER reads the query string (token-in-URL is a logging leak). Returns None if neither
    transport carries a non-empty token. The returned token is never logged by this module.
    """
    header = websocket.headers.get("authorization")
    if header and header.startswith(_BEARER_PREFIX):
        token = header[len(_BEARER_PREFIX) :].strip()
        if token:
            return token
    # Sec-WebSocket-Protocol is a comma-separated list of offered subprotocols. A JWT contains
    # only base64url + '.', never ',', so splitting on ',' is safe.
    offered = websocket.headers.get("sec-websocket-protocol")
    if offered:
        for candidate in offered.split(","):
            candidate = candidate.strip()
            if candidate.startswith(_SUBPROTOCOL_PREFIX):
                token = candidate[len(_SUBPROTOCOL_PREFIX) :]
                if token:
                    return token
    return None


async def _broadcast_presence(
    ctx: RuntimeContext, conn: Connection, status: str, *, audience: list[Connection] | None = None
) -> None:
    """Broadcast a presence.update to the connection's channel peers (never to itself)."""
    targets = audience if audience is not None else ctx.registry.sharing_connections(conn)
    frame = build_presence_update(tenant_id=conn.tenant_id, user_id=conn.user_id, status=status)
    for other in targets:
        if other is conn:
            continue
        await other.send(frame)


async def realtime_endpoint(websocket: WebSocket) -> None:
    """Authenticate the upgrade, then run the connection until it disconnects."""
    token = _extract_token(websocket)
    if token is None:
        await websocket.close(code=_CLOSE_POLICY_VIOLATION)
        return
    try:
        claims = verify(token, websocket.app.state.key_material)
    except TokenVerificationError:
        # Fail the handshake — no socket is opened. The token is never logged.
        await websocket.close(code=_CLOSE_POLICY_VIOLATION)
        return
    if "chat:read" not in claims.scope_set():
        await websocket.close(code=_CLOSE_POLICY_VIOLATION)
        return

    # Accept WITHOUT echoing any subprotocol (the bearer subprotocol value must never appear in
    # the handshake response).
    await websocket.accept()

    ctx: RuntimeContext = websocket.app.state.realtime_ctx
    conn = Connection(
        websocket=websocket,
        tenant_id=claims.tenant_id,
        user_id=claims.sub,
        scopes=claims.scope_set(),
    )

    # Deliverable channels = a SNAPSHOT of the user's memberships at connect (FORK B). Loaded
    # under the user's own tenant session, so RLS scopes it — only this tenant's channels.
    async with get_tenant_session(conn.tenant_id) as session:
        channel_ids = await chat_repo.channel_ids_for_user(
            session, tenant_id=conn.tenant_id, user_id=conn.user_id
        )
    conn.channels = set(channel_ids)

    ctx.registry.add(conn)
    await websocket.send_json(build_session_welcome(tenant_id=conn.tenant_id, user_id=conn.user_id))
    await _broadcast_presence(ctx, conn, "online")

    try:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            raw = message.get("text")
            if raw is None:
                # The catalog is JSON text frames; a binary frame is not a valid frame.
                await conn.send(
                    build_error(error_code="invalid_message", request_id=new_request_id())
                )
                continue
            try:
                await dispatch_frame(conn, raw, ctx)
            except Exception:  # noqa: BLE001 - a handler error must notify, not silently close
                # An unhandled handler error (e.g. the DB drops mid-persist) must NOT close the
                # socket silently — send the contracted internal_error frame and keep the
                # connection up. The fail-closed invariant holds: a send that errors before/at
                # persist was never committed and never fanned out.
                await conn.send(
                    build_error(error_code="internal_error", request_id=new_request_id())
                )
    finally:
        # Notify peers BEFORE removing this connection from the registry (afterwards it shares no
        # channel with anyone, so the audience would be empty).
        audience = [c for c in ctx.registry.sharing_connections(conn) if c is not conn]
        ctx.registry.discard(conn)
        await _broadcast_presence(ctx, conn, "offline", audience=audience)
        # R-007: a dropped socket ends any live 1-on-1 huddle this user was in — real telephony
        # semantics (a network drop ends the call), and it prevents a stale ringing/active huddle
        # from lingering in the single-instance manager after its last connection is gone. Only
        # fires when the disconnecting user has NO remaining live connection (multi-device: the
        # huddle stays up on their other sockets).
        if not ctx.registry.user_connections(conn.tenant_id, conn.user_id):
            ended = ctx.huddles.end_all_for_user(conn.tenant_id, conn.user_id)
            if ended is not None:
                # SHIELDED: by the time a dropped socket reaches this cleanup, Starlette/anyio
                # has already cancelled this connection's task-group scope. The archive write is
                # real socket I/O (a fresh DB connection) that actually suspends the coroutine —
                # an unshielded await here (or the peer send right after it) gets re-cancelled at
                # that suspension point, silently dropping the `ended` notice entirely (not just
                # the archive). Shielding this whole block — archive AND the peer send — is what
                # guarantees the disconnect-triggered peer still learns the huddle ended, exactly
                # as the pre-R-009 code already did before an actual DB round-trip was added here.
                with anyio.CancelScope(shield=True):
                    archive = await archive_ended_huddle_best_effort(
                        ended, ended_at=datetime.now(timezone.utc)
                    )
                    peer_id = ended.peer_of(conn.user_id)
                    for peer_conn in ctx.registry.user_connections(conn.tenant_id, peer_id):
                        await peer_conn.send(
                            build_huddle_update(
                                huddle_id=ended.huddle_id,
                                tenant_id=conn.tenant_id,
                                peer_user_id=conn.user_id,
                                state=HuddleState.ENDED.value,
                                archive=archive,
                            )
                        )
