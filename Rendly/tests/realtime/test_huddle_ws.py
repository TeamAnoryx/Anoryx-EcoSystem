"""R-007 1-on-1 huddle signaling — non-stubbed e2e over the real chat app + real ASGI WebSocket.

Mirrors ``test_chat_ws.py``'s posture: every test drives the REAL app (Starlette TestClient), no
mocks of the runtime itself. LIVE huddle state is ephemeral/in-memory (``realtime/huddle.py``,
ADR-0007), so most tests here assert only the wire behavior — but R-009 persists a real DB
record at the terminal ``ended`` transition, so a couple of tests below additionally read that
row back (real DB assertion, not a stub) to prove the hash chain the wire's ``archival`` object
claims actually landed in Postgres.

Every test ABOVE this line exercises the exactly-2-participant path and is UNMODIFIED from R-007
— proof that R-011 (group huddles, below) is additive, not a rewrite dressed as one (ADR-0011).
The group-huddle tests exercise the SAME wire (``contracts/messages.schema.json``) with
``participant_ids``/``to_user_id`` populated.
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
        # R-009: a real, DB-computed SHA-256 hex chain link + digest — never null on an ended
        # huddle (the DB archive write happens BEFORE this broadcast; see realtime/pipeline.py).
        assert ended1["archival"]["prev_record_hash"] is not None
        assert len(ended1["archival"]["prev_record_hash"]) == 64
        assert ended1["archival"]["content_hash"] is not None
        assert len(ended1["archival"]["content_hash"]) == 64
        # Both peers' frames describe the SAME archived record.
        assert ended2["archival"] == ended1["archival"]

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


def _huddle_row(tenant_id: str, huddle_id: str):
    """R-009: read the persisted session record back — a real DB read, not a stub."""
    from sqlalchemy import select

    from rendly.persistence.chat_models import HuddleRow
    from rendly.persistence.database import get_tenant_session

    with get_tenant_session(tenant_id) as s:
        return s.execute(
            select(HuddleRow).where(
                HuddleRow.tenant_id == tenant_id, HuddleRow.huddle_id == huddle_id
            )
        ).scalar_one()


def test_ended_huddle_is_persisted_with_a_real_hash_chain(
    make_client, seed_user, mint_token, new_uuid
):
    """R-009 non-stubbed e2e: the wire's ``archival`` object matches a REAL persisted row, and a
    second ended huddle for the SAME tenant chains from the first one's ``content_hash``."""
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    # First call: invite -> hangup -> ended.
    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        huddle_id_1 = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")
        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id_1})
        ended_1 = recv_until(ws1, "huddle.update")

    row_1 = _huddle_row(tenant, huddle_id_1)
    assert row_1.state == "ended"
    assert row_1.seq == 0
    assert row_1.content_hash == ended_1["archival"]["content_hash"]
    assert row_1.prev_record_hash == ended_1["archival"]["prev_record_hash"]

    from rendly.persistence import hash_chain

    assert row_1.prev_record_hash == hash_chain.HUDDLE_GENESIS_HASH

    # Second call, same tenant: chains from the first call's content_hash, seq advances to 1.
    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        huddle_id_2 = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")
        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id_2})
        recv_until(ws1, "huddle.update")

    row_2 = _huddle_row(tenant, huddle_id_2)
    assert row_2.seq == 1
    assert row_2.prev_record_hash == row_1.content_hash


# --- R-011: group huddles (2-8 participants, ADR-0011) ----------------------------------


def _open_and_drain(client, tokens: list[str]):
    """Open N websocket connections ONE AT A TIME (see the comment on the pre-existing busy-reply
    test above — simultaneous first connects race the async membership-snapshot read) and drain
    each one's session.welcome. Returns a context manager yielding the list of sockets, innermost
    (last-opened) LAST — i.e. ``sockets[0]`` is opened first, ``sockets[-1]`` opened last."""
    from contextlib import ExitStack

    stack = ExitStack()
    sockets = []
    for tok in tokens:
        ws = stack.enter_context(client.websocket_connect(_REALTIME, headers=_auth(tok)))
        ws.receive_json()
        sockets.append(ws)
    return stack, sockets


def test_group_invite_rings_all_participants_with_relative_participant_ids(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for u in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=u)
    client = make_client()
    tokens = [mint_token(user_id=u, tenant_id=tenant, scope=_FULL_SCOPE) for u in (u3, u2, u1)]

    stack, (ws3, ws2, ws1) = _open_and_drain(client, tokens)
    with stack:
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [u3]})
        u1_update = recv_until(ws1, "huddle.update")
        u2_update = recv_until(ws2, "huddle.update")
        u3_update = recv_until(ws3, "huddle.update")

        assert u1_update["state"] == u2_update["state"] == u3_update["state"] == "ringing"
        huddle_id = u1_update["huddle_id"]
        assert u2_update["huddle_id"] == huddle_id
        assert u3_update["huddle_id"] == huddle_id
        assert "archival" not in u1_update

        assert sorted(u1_update["participant_ids"]) == sorted([u2, u3])
        assert sorted(u2_update["participant_ids"]) == sorted([u1, u3])
        assert sorted(u3_update["participant_ids"]) == sorted([u1, u2])
        # Back-compat: peer_user_id always equals participant_ids[0] (contracts/messages.schema.json).
        for update in (u1_update, u2_update, u3_update):
            assert update["peer_user_id"] == update["participant_ids"][0]


def test_group_signal_without_to_user_id_is_ambiguous_for_3_plus(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for u in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=u)
    client = make_client()
    tokens = [mint_token(user_id=u, tenant_id=tenant, scope=_FULL_SCOPE) for u in (u3, u2, u1)]

    stack, (ws3, ws2, ws1) = _open_and_drain(client, tokens)
    with stack:
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [u3]})
        huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")
        recv_until(ws3, "huddle.update")

        # No to_user_id -> the server cannot infer a single implicit peer among 2 others.
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {"kind": "offer", "sdp": "v=0"},
            }
        )
        assert recv_until(ws1, "error")["error_code"] == "invalid_message"


def test_group_first_targeted_signal_activates_directly_and_routes_only_to_target(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for u in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=u)
    client = make_client()
    tokens = [mint_token(user_id=u, tenant_id=tenant, scope=_FULL_SCOPE) for u in (u3, u2, u1)]

    stack, (ws3, ws2, ws1) = _open_and_drain(client, tokens)
    with stack:
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [u3]})
        huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")
        recv_until(ws3, "huddle.update")

        # u2 signals u1 directly (to_user_id). u3 must NOT receive this relay.
        ws2.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "to_user_id": u1,
                "signal": {"kind": "answer", "sdp": "v=0 u2-to-u1"},
            }
        )
        relay = recv_until(ws1, "signal.relay")
        assert relay["from_user_id"] == u2
        assert relay["signal"]["sdp"] == "v=0 u2-to-u1"

        # `accepted` is skipped entirely for 3+ participants — straight to `active` for everyone
        # (ADR-0011 Fork C). recv_until(ws3, ...) would itself fail if the relay had wrongly
        # reached u3 first (it is not in the "transient" allow-list recv_until skips over).
        assert recv_until(ws1, "huddle.update")["state"] == "active"
        assert recv_until(ws2, "huddle.update")["state"] == "active"
        assert recv_until(ws3, "huddle.update")["state"] == "active"

        # A signal to someone not in the huddle is huddle_unavailable, not silently dropped.
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "to_user_id": str(uuid.uuid4()),
                "signal": {"kind": "offer", "sdp": "v=0"},
            }
        )
        assert recv_until(ws1, "error")["error_code"] == "huddle_unavailable"


def test_group_leave_shrinks_participant_ids_then_final_hangup_ends_and_archives(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for u in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=u)
    client = make_client()
    tokens = [mint_token(user_id=u, tenant_id=tenant, scope=_FULL_SCOPE) for u in (u3, u2, u1)]

    stack, (ws3, ws2, ws1) = _open_and_drain(client, tokens)
    with stack:
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [u3]})
        huddle_id = recv_until(ws1, "huddle.update")["huddle_id"]
        recv_until(ws2, "huddle.update")
        recv_until(ws3, "huddle.update")

        # Activate (any invitee's first signal -> active for a 3+ session).
        ws2.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "to_user_id": u1,
                "signal": {"kind": "answer", "sdp": "v=0"},
            }
        )
        recv_until(ws1, "signal.relay")
        assert recv_until(ws1, "huddle.update")["state"] == "active"
        assert recv_until(ws2, "huddle.update")["state"] == "active"
        assert recv_until(ws3, "huddle.update")["state"] == "active"

        # u3 leaves: 2 remain (u1, u2) -> stays active, shrunk participant_ids, no archival yet.
        ws3.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        u1_after_leave = recv_until(ws1, "huddle.update")
        u2_after_leave = recv_until(ws2, "huddle.update")
        assert u1_after_leave["state"] == "active"
        assert u2_after_leave["state"] == "active"
        assert u1_after_leave["participant_ids"] == [u2]
        assert u2_after_leave["participant_ids"] == [u1]
        assert "archival" not in u1_after_leave

        # u3 is no longer a participant — re-acting on the huddle now fails like any non-member.
        ws3.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        assert recv_until(ws3, "error")["error_code"] == "huddle_unavailable"

        # u1 hangs up: only u2 would remain -> the WHOLE session ends and archives, exactly like
        # an exactly-2-participant hangup, even though this session started with 3 invitees.
        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        ended1 = recv_until(ws1, "huddle.update")
        ended2 = recv_until(ws2, "huddle.update")
        assert ended1["state"] == "ended"
        assert ended2["state"] == "ended"
        assert ended1["archival"]["record_id"] == huddle_id
        assert ended2["archival"] == ended1["archival"]

    # R-009/R-011: the archived record's full roster is everyone EVER invited (u1, u2, u3), not
    # just the final 2 people left on the call (ADR-0011 Fork F implementation note).
    from sqlalchemy import select

    from rendly.persistence.chat_models import HuddleParticipantRow
    from rendly.persistence.database import get_tenant_session

    with get_tenant_session(tenant) as s:
        rows = (
            s.execute(
                select(HuddleParticipantRow.user_id).where(
                    HuddleParticipantRow.tenant_id == tenant,
                    HuddleParticipantRow.huddle_id == huddle_id,
                )
            )
            .scalars()
            .all()
        )
    assert set(rows) == {u1, u2, u3}

    row = _huddle_row(tenant, huddle_id)
    # 3 EVER-invited participants -> the convenience callee_id column is NULL (Fork F: only
    # populated for a session whose full roster was exactly 2).
    assert row.callee_id is None
    assert row.caller_id == u1


def test_group_invite_offline_invitee_is_huddle_unavailable(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    offline_u3 = new_uuid()  # never connects -> unreachable
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)

    with (
        client.websocket_connect(_REALTIME, headers=_auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=_auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json(
            {"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [offline_u3]}
        )
        assert recv_until(ws1, "error")["error_code"] == "huddle_unavailable"


def test_group_invite_busy_invitee_reports_that_invitee_as_busy(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3, u4 = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    for u in (u1, u2, u3, u4):
        seed_user(tenant_id=tenant, user_id=u)
    client = make_client()
    tokens = [mint_token(user_id=u, tenant_id=tenant, scope=_FULL_SCOPE) for u in (u4, u3, u2, u1)]

    stack, (ws4, ws3, ws2, ws1) = _open_and_drain(client, tokens)
    with stack:
        # u3 is already mid-call with u4 -> busy.
        ws3.send_json({"msg_type": "huddle.invite", "peer_user_id": u4})
        recv_until(ws3, "huddle.update")
        recv_until(ws4, "huddle.update")

        # u1 invites u2 (reachable, free) and u3 (reachable, but busy) -> NO session is created;
        # only the caller learns, and it names u3 specifically (the first failing invitee).
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [u3]})
        busy = recv_until(ws1, "huddle.update")
        assert busy["state"] == "busy"
        assert busy["peer_user_id"] == u3
        assert busy["participant_ids"] == [u3]

        # The throwaway busy huddle_id was never registered -> unusable by anyone, proving u1's
        # failed group invite left no session behind (mirrors the original 1-on-1 busy posture).
        ws4.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": busy["huddle_id"],
                "signal": {"kind": "answer", "sdp": "v=0"},
            }
        )
        assert recv_until(ws4, "error")["error_code"] == "huddle_unavailable"


def test_group_invite_duplicate_invitee_is_invalid_message(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        ws.receive_json()
        ws.send_json({"msg_type": "huddle.invite", "peer_user_id": u2, "participant_ids": [u2]})
        assert recv_until(ws, "error")["error_code"] == "invalid_message"


def test_group_invite_participant_ids_over_cap_is_invalid_message(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    # HuddleInvite.participant_ids maxItems is 6 (contracts/messages.schema.json) -> 7 overflows.
    too_many = [str(uuid.uuid4()) for _ in range(7)]
    with client.websocket_connect(_REALTIME, headers=_auth(tok)) as ws:
        ws.receive_json()
        ws.send_json(
            {
                "msg_type": "huddle.invite",
                "peer_user_id": str(uuid.uuid4()),
                "participant_ids": too_many,
            }
        )
        assert recv_until(ws, "error")["error_code"] == "invalid_message"
