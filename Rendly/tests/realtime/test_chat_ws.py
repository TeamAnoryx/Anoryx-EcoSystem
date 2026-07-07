"""R-005 WebSocket chat — non-stubbed e2e on real Postgres + real in-process ASGI WebSocket.

Every test drives the REAL chat app (Starlette TestClient = the real ASGI app, not a stub),
persists to a REAL local Postgres, and asserts DB state with a SYNC privileged read. The security
spine — tenant isolation + the fail-closed inspection seam — is proven against live delivery and
live rows, not mocks.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from starlette.websockets import WebSocketDisconnect

from chatdata import (
    AllBlockInspector,
    MarkerBlockInspector,
    RaisingInspector,
    UnavailableInspector,
    recv_until,
)

_REALTIME = "/v1/realtime"
# A full-capability operator token covers create + admin + chat read/write for setup convenience.
_FULL_SCOPE = "channels:write channels:admin chat:read chat:write"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _messages(tenant_id: str, channel_id: str) -> list:
    from rendly.persistence.database import get_privileged_session

    with get_privileged_session() as session:
        return (
            session.execute(
                text(
                    "SELECT message_id, content, seq, sender_user_id, inspection_status "
                    "FROM rendly.messages WHERE tenant_id=:t AND channel_id=:c ORDER BY seq"
                ),
                {"t": tenant_id, "c": channel_id},
            )
            .mappings()
            .all()
        )


def _make_channel_with_members(client, *, owner_token, member_ids_tokens, name="eng"):
    """Create a channel as the owner, add each (user_id, role) member; return the channel id."""
    resp = client.post(
        "/v1/channels", json={"name": name, "type": "private"}, headers=_auth(owner_token)
    )
    assert resp.status_code == 201, resp.text
    channel_id = resp.json()["channel_id"]
    for user_id, role in member_ids_tokens:
        r = client.put(
            f"/v1/channels/{channel_id}/members/{user_id}",
            json={"role": role},
            headers=_auth(owner_token),
        )
        assert r.status_code == 200, r.text
    return channel_id


def test_real_ws_roundtrip_persists_and_delivers(make_client, seed_user, mint_token, new_uuid):
    """token-authed connect -> chat.send -> persisted in real PG -> delivered to a 2nd member."""
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    u2_tok = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read")

    channel_id = _make_channel_with_members(
        client, owner_token=owner_tok, member_ids_tokens=[(u2, "member")]
    )

    with (
        client.websocket_connect(_REALTIME, headers=_auth(u2_tok)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(u1_tok)) as ws1,
    ):
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        assert ws1.receive_json()["msg_type"] == "session.welcome"

        ws1.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-roundtrip-1",
                "channel_id": channel_id,
                "content": "hello real postgres",
                "content_type": "text",
            }
        )
        ack = recv_until(ws1, "chat.ack")
        assert ack["status"] == "accepted"
        assert ack["client_msg_id"] == "c-roundtrip-1"
        assert ack["channel_id"] == channel_id
        assert ack["tenant_id"] == tenant
        message_id = ack["message_id"]

        delivered_to_sender = recv_until(ws1, "chat.message")
        delivered_to_other = recv_until(ws2, "chat.message")

    # Delivered frame conforms to the locked chat.message shape.
    for frame in (delivered_to_sender, delivered_to_other):
        assert frame["message_id"] == message_id
        assert frame["tenant_id"] == tenant
        assert frame["channel_id"] == channel_id
        assert frame["sender_user_id"] == u1
        assert frame["content"] == "hello real postgres"
        assert frame["content_type"] == "text"
        assert frame["archival"]["schema_version"] == "1"
        assert frame["archival"]["record_id"] == message_id
        assert frame["archival"]["seq"] == 0
        assert frame["archival"]["prev_record_hash"] is None  # RESERVED (R-009)
        assert frame["archival"]["content_hash"] is None
        assert frame["inspection"]["status"] == "pass"

    # Persisted exactly once in real Postgres.
    rows = _messages(tenant, channel_id)
    assert len(rows) == 1
    assert rows[0]["message_id"] == message_id
    assert rows[0]["content"] == "hello real postgres"
    assert rows[0]["seq"] == 0
    assert rows[0]["inspection_status"] == "pass"


def test_seam_block_not_persisted_not_delivered(make_client, seed_user, mint_token, new_uuid):
    """A rejecting seam -> chat.ack blocked, message NOT in DB, NOT delivered (fail-closed)."""
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    # Block only the marked content; a following clean message passes — so the clean one arriving
    # FIRST at the receiver proves the blocked one never went out.
    client = make_client(inspector=MarkerBlockInspector("BLOCKME"))
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    u2_tok = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read")
    channel_id = _make_channel_with_members(
        client, owner_token=owner_tok, member_ids_tokens=[(u2, "member")]
    )

    with (
        client.websocket_connect(_REALTIME, headers=_auth(u2_tok)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(u1_tok)) as ws1,
    ):
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        assert ws1.receive_json()["msg_type"] == "session.welcome"

        # 1) Blocked send.
        ws1.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-blocked",
                "channel_id": channel_id,
                "content": "please BLOCKME now",
            }
        )
        ack = recv_until(ws1, "chat.ack")
        assert ack["status"] == "blocked"
        assert ack["error_code"] == "message_blocked"
        assert "message_id" not in ack
        assert ack["inspection"]["status"] == "blocked"

        # Nothing persisted yet.
        assert _messages(tenant, channel_id) == []

        # 2) Clean send passes and is delivered.
        ws1.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-clean",
                "channel_id": channel_id,
                "content": "delivered-ok",
            }
        )
        ack2 = recv_until(ws1, "chat.ack")
        assert ack2["status"] == "accepted"
        # The FIRST chat.message the receiver sees is the clean one — the blocked one never went out.
        received = recv_until(ws2, "chat.message")
        assert received["content"] == "delivered-ok"

    rows = _messages(tenant, channel_id)
    assert len(rows) == 1
    assert rows[0]["content"] == "delivered-ok"


@pytest.mark.parametrize("inspector", [UnavailableInspector(), RaisingInspector()])
def test_seam_unavailable_fails_closed(make_client, seed_user, mint_token, new_uuid, inspector):
    """A seam that cannot complete (returns seam_unavailable OR raises) -> fail-closed BLOCK."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client(inspector=inspector)
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    channel_id = _make_channel_with_members(client, owner_token=owner_tok, member_ids_tokens=[])

    with client.websocket_connect(_REALTIME, headers=_auth(u1_tok)) as ws1:
        assert ws1.receive_json()["msg_type"] == "session.welcome"
        ws1.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-unavail",
                "channel_id": channel_id,
                "content": "whatever",
            }
        )
        ack = recv_until(ws1, "chat.ack")
        assert ack["status"] == "blocked"
        assert ack["error_code"] == "inspection_unavailable"
        assert "message_id" not in ack

    assert _messages(tenant, channel_id) == []  # never persisted on a fail-closed block


def test_cross_tenant_no_delivery_and_registry_is_tenant_pure(
    make_client, seed_user, mint_token, new_uuid
):
    """A tenant-A connection never receives tenant-B's channel messages."""
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    client = make_client()
    a_owner = mint_token(user_id=ua, tenant_id=ta, scope=_FULL_SCOPE)
    b_owner = mint_token(user_id=ub, tenant_id=tb, scope=_FULL_SCOPE)
    a_tok = mint_token(user_id=ua, tenant_id=ta, scope="chat:read chat:write")
    b_tok = mint_token(user_id=ub, tenant_id=tb, scope="chat:read chat:write")

    ca = _make_channel_with_members(
        client, owner_token=a_owner, member_ids_tokens=[], name="A-chan"
    )
    cb = _make_channel_with_members(
        client, owner_token=b_owner, member_ids_tokens=[], name="B-chan"
    )

    with (
        client.websocket_connect(_REALTIME, headers=_auth(a_tok)) as ws_a,
        client.websocket_connect(_REALTIME, headers=_auth(b_tok)) as ws_b,
    ):
        assert ws_a.receive_json()["msg_type"] == "session.welcome"
        assert ws_b.receive_json()["msg_type"] == "session.welcome"

        # Every registry bucket is tenant-pure (a (tenant, channel) bucket holds only that tenant's
        # connections) — the structural half of cross-tenant delivery isolation.
        registry = client.app.state.realtime_ctx.registry
        for (bucket_tenant, _channel), conns in registry._by_channel.items():
            for conn in conns:
                assert conn.tenant_id == bucket_tenant

        # tenant B sends on its own channel; tenant B receives it.
        ws_b.send_json(
            {"msg_type": "chat.send", "client_msg_id": "c-b", "channel_id": cb, "content": "from-B"}
        )
        assert recv_until(ws_b, "chat.ack")["status"] == "accepted"
        assert recv_until(ws_b, "chat.message")["content"] == "from-B"

        # tenant A sends on ITS channel; the FIRST chat.message A sees is its own (from-A), proving
        # tenant B's message was never delivered to A.
        ws_a.send_json(
            {"msg_type": "chat.send", "client_msg_id": "c-a", "channel_id": ca, "content": "from-A"}
        )
        assert recv_until(ws_a, "chat.ack")["status"] == "accepted"
        a_msg = recv_until(ws_a, "chat.message")
        assert a_msg["channel_id"] == ca
        assert a_msg["content"] == "from-A"


def test_token_in_url_is_rejected(make_client, seed_user, mint_token, new_uuid):
    """A token in the query string is NOT a valid transport — the handshake fails, no socket."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"{_REALTIME}?access_token={tok}") as ws:
            ws.receive_json()


def test_subprotocol_bearer_authenticates(make_client, seed_user, mint_token, new_uuid):
    """The rendly.bearer.<jwt> subprotocol transport authenticates the handshake."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read")
    with client.websocket_connect(_REALTIME, subprotocols=[f"rendly.bearer.{tok}"]) as ws:
        welcome = ws.receive_json()
        assert welcome["msg_type"] == "session.welcome"
        assert welcome["tenant_id"] == tenant
        assert welcome["user_id"] == u1


def test_missing_token_rejected(make_client, new_uuid):
    """No token via any transport -> handshake fails (no socket opened)."""
    client = make_client()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(_REALTIME) as ws:
            ws.receive_json()


def test_send_without_chat_write_is_unauthorized(make_client, seed_user, mint_token, new_uuid):
    """A read-only token may open the socket, but its chat.send is rejected (per-frame chat:write)."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    read_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read")  # NO chat:write
    channel_id = _make_channel_with_members(client, owner_token=owner_tok, member_ids_tokens=[])

    with client.websocket_connect(_REALTIME, headers=_auth(read_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-noscope",
                "channel_id": channel_id,
                "content": "should be rejected",
            }
        )
        err = recv_until(ws, "error")
        assert err["error_code"] == "unauthorized"

    assert _messages(tenant, channel_id) == []


def test_message_too_large_is_blocked(make_client, seed_user, mint_token, new_uuid):
    """content over 16 KiB -> chat.ack blocked message_too_large (before authz; nothing persisted)."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    channel_id = str(uuid.uuid4())  # need not exist; size is checked before authz
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-big",
                "channel_id": channel_id,
                "content": "x" * 16385,
            }
        )
        ack = recv_until(ws, "chat.ack")
        assert ack["status"] == "blocked"
        assert ack["error_code"] == "message_too_large"


def test_server_only_huddle_frame_from_client_answered_unavailable(
    make_client, seed_user, mint_token, new_uuid
):
    """A client sending a SERVER->client-only catalog frame (R-007: huddle.update/signal.relay)
    is answered huddle_unavailable, not dropped — huddle.invite/hangup/signal.send are the real
    client->server operations (see test_chat_huddles.py)."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {
                "msg_type": "huddle.update",
                "huddle_id": str(uuid.uuid4()),
                "tenant_id": tenant,
                "peer_user_id": str(uuid.uuid4()),
                "state": "ringing",
            }
        )
        err = recv_until(ws, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_all_block_inspector_blocks_every_message(make_client, seed_user, mint_token, new_uuid):
    """Sanity: an unconditional block inspector blocks a normal message too (no marker needed)."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client(inspector=AllBlockInspector())
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    channel_id = _make_channel_with_members(client, owner_token=owner_tok, member_ids_tokens=[])
    with client.websocket_connect(_REALTIME, headers=_auth(u1_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {
                "msg_type": "chat.send",
                "client_msg_id": "c-x",
                "channel_id": channel_id,
                "content": "hi",
            }
        )
        ack = recv_until(ws, "chat.ack")
        assert ack["status"] == "blocked"
        assert ack["error_code"] == "message_blocked"
    assert _messages(tenant, channel_id) == []
