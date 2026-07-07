"""R-007 1-on-1 huddle signaling — non-stubbed e2e over the real chat app + real ASGI WebSocket.

Mirrors ``test_chat_ws.py``'s posture: every test drives the REAL app (Starlette TestClient), no
mocks of the runtime itself. Huddles are ephemeral/in-memory (``realtime/huddle.py``, ADR-0007),
so there is no DB assertion here — but the suite still lives in ``tests/realtime`` (the DB-backed
lane) because it needs the real chat app (auth + WS + registry), same as the chat suite.
"""

from __future__ import annotations

import uuid

from chatdata import recv_until

_REALTIME = "/v1/realtime"
_FULL_SCOPE = "chat:read chat:write huddle:initiate"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_invite_rings_both_peers(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        assert ws1.receive_json()["msg_type"] == "session.welcome"

        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})

        caller_update = recv_until(ws1, "huddle.update")
        callee_update = recv_until(ws2, "huddle.update")
        assert caller_update["state"] == "ringing"
        assert callee_update["state"] == "ringing"
        assert caller_update["huddle_id"] == callee_update["huddle_id"]
        assert caller_update["tenant_id"] == tenant
        # peer_user_id is relative to the RECIPIENT.
        assert caller_update["peer_user_id"] == u2
        assert callee_update["peer_user_id"] == u1
        assert "archival" not in caller_update


def test_full_lifecycle_signal_relay_accept_active_then_hangup_ends(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()

        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")

        # The CALLEE signals first (their SDP answer) -> implicit accept.
        ws2.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {"kind": "answer", "sdp": "v=0 answer"},
            }
        )
        relay1 = recv_until(ws1, "signal.relay")
        assert relay1["from_user_id"] == u2
        assert relay1["signal"] == {"kind": "answer", "sdp": "v=0 answer"}
        assert recv_until(ws1, "huddle.update")["state"] == "accepted"
        assert recv_until(ws2, "huddle.update")["state"] == "accepted"

        # The CALLER signals next (an ICE candidate) -> active.
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {
                    "kind": "ice-candidate",
                    "candidate": "candidate:1 1 UDP 2130706431 192.0.2.1 54321 typ host",
                    "sdp_mid": "0",
                    "sdp_mline_index": 0,
                },
            }
        )
        relay2 = recv_until(ws2, "signal.relay")
        assert relay2["from_user_id"] == u1
        assert relay2["signal"]["kind"] == "ice-candidate"
        assert recv_until(ws1, "huddle.update")["state"] == "active"
        assert recv_until(ws2, "huddle.update")["state"] == "active"

        # A further signal while already active relays but does NOT re-announce a state change.
        ws2.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {
                    "kind": "ice-candidate",
                    "candidate": "candidate:2 1 UDP 1 1.1.1.1 1 typ host",
                },
            }
        )
        assert recv_until(ws1, "signal.relay")["from_user_id"] == u2

        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        ended1 = recv_until(ws1, "huddle.update")
        ended2 = recv_until(ws2, "huddle.update")
        assert ended1["state"] == "ended"
        assert ended2["state"] == "ended"
        assert ended1["archival"]["record_id"] == huddle_id
        assert ended1["archival"]["schema_version"] == "1"
        assert isinstance(ended1["archival"]["seq"], int)
        assert ended1["archival"]["prev_record_hash"] is None
        assert ended1["archival"]["content_hash"] is None

        # The huddle is now terminal/released — a further signal on it is unavailable.
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {"kind": "offer", "sdp": "v=0 stale"},
            }
        )
        assert recv_until(ws1, "error")["error_code"] == "huddle_unavailable"


def test_callee_hangup_while_ringing_declines(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")

        ws2.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        declined1 = recv_until(ws1, "huddle.update")
        declined2 = recv_until(ws2, "huddle.update")
        assert declined1["state"] == "declined"
        assert declined2["state"] == "declined"
        assert "archival" not in declined1  # only a durable ("ended") record carries archival


def test_caller_hangup_while_ringing_ends_not_declines(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")

        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        assert recv_until(ws1, "huddle.update")["state"] == "ended"
        assert recv_until(ws2, "huddle.update")["state"] == "ended"


def test_busy_reply_is_caller_only_and_does_not_disturb_the_active_huddle(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    seed_user(tenant_id=tenant, user_id=u3)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)
    t3 = mint_token(user_id=u3, tenant_id=tenant, scope=_FULL_SCOPE)

    # Connections are opened and drained ONE AT A TIME (not via one combined `with (...)`) so
    # each connection's connect-time async DB read (its membership snapshot) fully completes
    # before the next connection starts — three truly-simultaneous first connects on the async
    # engine is a harness-level race unrelated to R-007's own logic.
    with client.websocket_connect(_REALTIME, headers=_auth(t3)) as ws3:
        ws3.receive_json()
        with client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2:
            ws2.receive_json()
            with client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1:
                ws1.receive_json()

                ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
                real_huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
                recv_until(ws2, "huddle.update")

                # u3 tries to call u2 while u2 is already ringing with u1 -> busy, u2 is never told.
                ws3.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
                busy = recv_until(ws3, "huddle.update")
                assert busy["state"] == "busy"
                assert busy["peer_user_id"] == u2
                assert busy["huddle_id"] != real_huddle_id  # a throwaway id — never registered

                # The real huddle is untouched: it still accepts a signal normally.
                ws2.send_json(
                    {
                        "msg_type": "signal.send",
                        "huddle_id": real_huddle_id,
                        "signal": {"kind": "answer", "sdp": "v=0"},
                    }
                )
                assert recv_until(ws1, "signal.relay")["huddle_id"] == real_huddle_id
                assert recv_until(ws1, "huddle.update")["state"] == "accepted"
                assert recv_until(ws2, "huddle.update")["state"] == "accepted"


def test_invite_self_is_invalid_message(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        ws.receive_json()
        ws.send_json({"msg_type": "huddle.invite", "peer_user_id": u1})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"


def test_invite_without_scope_is_unauthorized(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    caller_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    callee_tok = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)
    with (
        client.websocket_connect(_REALTIME, headers=_auth(callee_tok)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(caller_tok)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        assert recv_until(ws1, "error")["error_code"] == "unauthorized"


def test_invite_offline_peer_is_huddle_unavailable(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        ws.receive_json()
        ws.send_json({"msg_type": "huddle.invite", "peer_user_id": str(uuid.uuid4())})
        assert recv_until(ws, "error")["error_code"] == "huddle_unavailable"


def test_signal_and_hangup_on_unknown_huddle_is_huddle_unavailable(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    fake_huddle_id = str(uuid.uuid4())
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        ws.receive_json()
        ws.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": fake_huddle_id,
                "signal": {"kind": "offer", "sdp": "v=0"},
            }
        )
        assert recv_until(ws, "error")["error_code"] == "huddle_unavailable"
        ws.send_json({"msg_type": "huddle.hangup", "huddle_id": fake_huddle_id})
        assert recv_until(ws, "error")["error_code"] == "huddle_unavailable"


def test_non_participant_cannot_signal_or_hangup_another_huddle(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    seed_user(tenant_id=tenant, user_id=u3)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)
    t3 = mint_token(user_id=u3, tenant_id=tenant, scope=_FULL_SCOPE)
    # Opened + drained one at a time — see the comment in the busy-reply test above.
    with client.websocket_connect(_REALTIME, headers=_auth(t3)) as ws3:
        ws3.receive_json()
        with client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2:
            ws2.receive_json()
            with client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1:
                ws1.receive_json()
                ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
                huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
                recv_until(ws2, "huddle.update")

                ws3.send_json(
                    {
                        "msg_type": "signal.send",
                        "huddle_id": huddle_id,
                        "signal": {"kind": "offer", "sdp": "v=0"},
                    }
                )
                assert recv_until(ws3, "error")["error_code"] == "huddle_unavailable"
                ws3.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
                assert recv_until(ws3, "error")["error_code"] == "huddle_unavailable"

                # Untouched: the real participants can still proceed normally.
                ws2.send_json(
                    {
                        "msg_type": "signal.send",
                        "huddle_id": huddle_id,
                        "signal": {"kind": "answer", "sdp": "v=0"},
                    }
                )
                assert recv_until(ws1, "signal.relay")["from_user_id"] == u2


def test_invalid_signal_and_invite_shape_is_invalid_message(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        ws.receive_json()
        # peer_user_id missing entirely.
        ws.send_json({"msg_type": "huddle.invite"})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"
        # An unrecognized `signal.kind` fails the closed discriminated union.
        ws.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": str(uuid.uuid4()),
                "signal": {"kind": "bogus"},
            }
        )
        assert recv_until(ws, "error")["error_code"] == "invalid_message"
        # A server->client-only frame type sent inbound is not in the dispatch table.
        ws.send_json({"msg_type": "signal.relay"})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"
        # huddle.hangup missing its required huddle_id.
        ws.send_json({"msg_type": "huddle.hangup"})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"


def test_disconnect_ends_active_huddle_for_the_peer(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1:
        ws1.receive_json()
        with client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2:
            ws2.receive_json()
            ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
            huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
            recv_until(ws2, "huddle.update")
        # ws2's `with` block exited -> the socket disconnected while still "ringing".
        ended = recv_until(ws1, "huddle.update")
        assert ended["state"] == "ended"
        assert ended["huddle_id"] == huddle_id
        assert ended["peer_user_id"] == u2


def test_multi_device_disconnect_only_ends_when_the_last_socket_closes(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2a = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)
    t2b = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1:
        ws1.receive_json()
        with client.websocket_connect(_REALTIME, headers=_auth(t2a)) as ws2a:
            ws2a.receive_json()
            with client.websocket_connect(_REALTIME, headers=_auth(t2b)) as ws2b:
                ws2b.receive_json()
                ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
                huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
                recv_until(ws2a, "huddle.update")
                recv_until(ws2b, "huddle.update")
            # ws2b closed but ws2a (same user, second device) is still live -> the huddle
            # survives: u2's remaining device can still answer on it.
            ws2a.send_json(
                {
                    "msg_type": "signal.send",
                    "huddle_id": huddle_id,
                    "signal": {"kind": "answer", "sdp": "still-up"},
                }
            )
            assert recv_until(ws1, "signal.relay")["signal"]["sdp"] == "still-up"
