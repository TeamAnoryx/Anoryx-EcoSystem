"""R-005 typing + presence + read receipts + frame-error handling (real WS e2e).

Verifies the chat-family frames beyond send/deliver: typing.update / presence.update broadcasts,
the connect/disconnect presence lifecycle, the chat.read no-op, and the dispatcher's error answers
for malformed / unknown / binary frames.
"""

from __future__ import annotations

from chatdata import auth, make_channel, recv_until

_REALTIME = "/v1/realtime"
_FULL = "channels:write channels:admin chat:read chat:write"


def test_typing_set_broadcasts_typing_update_to_other_members(
    make_client, seed_user, mint_token, new_uuid
):
    tenant, u1, u2 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    owner = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    u2_tok = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read")
    cid = make_channel(client, owner, members=[(u2, "member")])

    with (
        client.websocket_connect(_REALTIME, headers=auth(u2_tok)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(u1_tok)) as ws1,
    ):
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        assert ws1.receive_json()["msg_type"] == "session.welcome"

        ws1.send_json({"msg_type": "typing.set", "channel_id": cid, "state": "start"})
        update = recv_until(ws2, "typing.update")
        assert update["channel_id"] == cid
        assert update["user_id"] == u1
        assert update["state"] == "start"
        assert update["tenant_id"] == tenant


def test_presence_set_and_connect_disconnect_lifecycle(
    make_client, seed_user, mint_token, new_uuid
):
    tenant, u1, u2 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    owner = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    u2_tok = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read")
    make_channel(client, owner, members=[(u2, "member")])  # u1+u2 share a channel (presence peers)

    with client.websocket_connect(_REALTIME, headers=auth(u2_tok)) as ws2:
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        # u1 connecting broadcasts presence online to the channel peer u2.
        with client.websocket_connect(_REALTIME, headers=auth(u1_tok)) as ws1:
            assert ws1.receive_json()["msg_type"] == "session.welcome"
            online = recv_until(ws2, "presence.update")
            assert online["user_id"] == u1
            assert online["status"] == "online"

            # u1 sets presence away -> u2 sees presence.update away.
            ws1.send_json({"msg_type": "presence.set", "status": "away"})
            away = recv_until(ws2, "presence.update")
            assert away["user_id"] == u1
            assert away["status"] == "away"
        # u1 disconnected (left the with-block) -> u2 sees presence.update offline.
        offline = recv_until(ws2, "presence.update")
        assert offline["user_id"] == u1
        assert offline["status"] == "offline"


def test_chat_read_valid_is_noop_invalid_is_error(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    with client.websocket_connect(_REALTIME, headers=auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        # A valid chat.read produces NO response (no server fan-out frame exists for it).
        ws.send_json(
            {
                "msg_type": "chat.read",
                "channel_id": new_uuid(),
                "up_to_message_id": new_uuid(),
            }
        )
        # A following invalid chat.read produces an error — and arriving FIRST proves the valid one
        # produced nothing and the connection survived the no-op.
        ws.send_json({"msg_type": "chat.read", "channel_id": "not-a-uuid", "up_to_message_id": "x"})
        err = recv_until(ws, "error")
        assert err["error_code"] == "invalid_message"


def test_malformed_and_unknown_frames_get_error(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    with client.websocket_connect(_REALTIME, headers=auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"

        ws.send_text("this is not json")
        assert recv_until(ws, "error")["error_code"] == "invalid_message"

        ws.send_json(["not", "an", "object"])
        assert recv_until(ws, "error")["error_code"] == "invalid_message"

        ws.send_json({"msg_type": "totally.unknown"})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"

        ws.send_bytes(b"\x00\x01\x02 binary frame")
        assert recv_until(ws, "error")["error_code"] == "invalid_message"


def test_presence_set_invalid_status_is_error(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    with client.websocket_connect(_REALTIME, headers=auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json({"msg_type": "presence.set", "status": "invisible"})  # not a valid status
        assert recv_until(ws, "error")["error_code"] == "invalid_message"


def test_typing_for_non_member_channel_is_silently_ignored(
    make_client, seed_user, mint_token, new_uuid
):
    """typing.set for a channel the connection does not deliver is dropped (no broadcast, no error)."""
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    owner = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    make_channel(client, owner)  # u1 is the sole member
    with client.websocket_connect(_REALTIME, headers=auth(u1_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        # typing for a channel NOT in the connection's snapshot -> ignored (no DB hit, no broadcast).
        ws.send_json({"msg_type": "typing.set", "channel_id": new_uuid(), "state": "start"})
        # A following invalid frame yields an error first -> proves the ignored typing emitted nothing.
        ws.send_json({"msg_type": "typing.set", "channel_id": "bad", "state": "start"})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"
