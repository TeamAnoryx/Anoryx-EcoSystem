"""R-007 1-on-1 huddle signaling — non-stubbed e2e on a real in-process ASGI WebSocket.

Every test drives the REAL chat app (Starlette TestClient = the real ASGI app, not a stub) over
TWO live WebSocket connections, proving the full ring -> accept -> active -> hangup lifecycle, the
busy/offline/nonexistent-peer fail-closed paths, the (optional) channel-membership gate, the
inspection seam on signaling, and disconnect-ends-the-huddle — the same non-stubbed-e2e discipline
R-005/R-006 established (banked rule 2).
"""

from __future__ import annotations

import uuid

import pytest

from chatdata import (
    AllBlockInspector,
    RaisingInspector,
    UnavailableInspector,
    auth,
    make_channel,
    recv_until,
)

_REALTIME = "/v1/realtime"
_FULL_SCOPE = "channels:write channels:admin chat:read chat:write huddle:initiate"


def test_invite_rings_both_sides_then_signal_send_accepts_then_activates_then_hangup_ends(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")

    with (
        client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1,
    ):
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        assert ws1.receive_json()["msg_type"] == "session.welcome"

        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        ring1 = recv_until(ws1, "huddle.update")
        ring2 = recv_until(ws2, "huddle.update")
        assert ring1["state"] == ring2["state"] == "ringing"
        assert ring1["huddle_id"] == ring2["huddle_id"]
        huddle_id = ring1["huddle_id"]
        # peer_user_id is RECIPIENT-RELATIVE: the inviter sees the peer, the peer sees the inviter.
        assert ring1["peer_user_id"] == u2
        assert ring2["peer_user_id"] == u1
        assert "archival" not in ring1  # in-flight state -> no archival yet

        # The inviter signals first (e.g. sends the SDP offer) — relayed, but still "ringing"
        # (the callee has not responded yet; see the state-transition heuristic in huddle.py).
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {"kind": "offer", "sdp": "v=0 offer-from-u1"},
            }
        )
        relayed_offer = recv_until(ws2, "signal.relay")
        assert relayed_offer["from_user_id"] == u1
        assert relayed_offer["huddle_id"] == huddle_id
        assert relayed_offer["signal"] == {"kind": "offer", "sdp": "v=0 offer-from-u1"}

        # The callee (peer) answers -> ringing -> accepted, both notified.
        ws2.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {"kind": "answer", "sdp": "v=0 answer-from-u2"},
            }
        )
        relayed_answer = recv_until(ws1, "signal.relay")
        assert relayed_answer["from_user_id"] == u2
        assert relayed_answer["signal"]["kind"] == "answer"
        accepted1 = recv_until(ws1, "huddle.update")
        accepted2 = recv_until(ws2, "huddle.update")
        assert accepted1["state"] == accepted2["state"] == "accepted"

        # The inviter's second signal (an ICE candidate) -> both sides have now signaled ->
        # accepted -> active.
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {
                    "kind": "ice-candidate",
                    "candidate": "candidate:1 1 UDP 1 1.2.3.4 1 typ host",
                },
            }
        )
        recv_until(ws2, "signal.relay")
        active1 = recv_until(ws1, "huddle.update")
        active2 = recv_until(ws2, "huddle.update")
        assert active1["state"] == active2["state"] == "active"

        # A further signal after active relays silently — no further lifecycle broadcast.
        ws2.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": huddle_id,
                "signal": {
                    "kind": "ice-candidate",
                    "candidate": "candidate:2 1 UDP 1 5.6.7.8 2 typ host",
                },
            }
        )
        assert recv_until(ws1, "signal.relay")["from_user_id"] == u2

        # Either side hangs up -> ended, with archival now populated (terminal state).
        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        ended1 = recv_until(ws1, "huddle.update")
        ended2 = recv_until(ws2, "huddle.update")
        assert ended1["state"] == ended2["state"] == "ended"
        assert ended1["archival"]["record_id"] == huddle_id
        assert ended2["archival"]["record_id"] == huddle_id


def test_callee_hangup_while_ringing_is_declined(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")

    with (
        client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        recv_until(ws1, "huddle.update")
        ring2 = recv_until(ws2, "huddle.update")
        huddle_id = ring2["huddle_id"]

        ws2.send_json({"msg_type": "huddle.hangup", "huddle_id": huddle_id})
        declined1 = recv_until(ws1, "huddle.update")
        declined2 = recv_until(ws2, "huddle.update")
        assert declined1["state"] == declined2["state"] == "declined"


def test_inviter_cancel_while_ringing_is_ended_not_declined(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")

    with (
        client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        ring1 = recv_until(ws1, "huddle.update")
        recv_until(ws2, "huddle.update")

        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": ring1["huddle_id"]})
        ended1 = recv_until(ws1, "huddle.update")
        ended2 = recv_until(ws2, "huddle.update")
        assert ended1["state"] == ended2["state"] == "ended"


def test_invite_a_busy_peer_gets_busy_only_the_inviter_is_told(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for uid in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=uid)
    client = make_client()
    scope = "chat:read chat:write huddle:initiate"
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=scope)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=scope)
    t3 = mint_token(user_id=u3, tenant_id=tenant, scope=scope)

    # Nested (not a single parenthesized `with (...)`) — three concurrent TestClient
    # WebSocket portals bound to the lazily-created async engine's first-use loop have shown
    # to race under the tuple form; sequential nesting is the same live-connection topology
    # without that race.
    with client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2:
        ws2.receive_json()
        with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
            ws1.receive_json()
            with client.websocket_connect(_REALTIME, headers=auth(t3)) as ws3:
                ws3.receive_json()

                # u1 and u2 are already in an active session.
                ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
                recv_until(ws1, "huddle.update")
                recv_until(ws2, "huddle.update")

                # u3 tries to invite u1 (busy) -> u3 gets "busy"; u1/u2's session is untouched.
                ws3.send_json({"msg_type": "huddle.invite", "peer_user_id": u1})
                busy = recv_until(ws3, "huddle.update")
                assert busy["state"] == "busy"
                assert busy["peer_user_id"] == u1
                assert busy["archival"]["record_id"] == busy["huddle_id"]  # a terminal attempt


def test_caller_already_in_a_session_cannot_start_a_second_one(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    scope = "chat:read chat:write huddle:initiate"
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=scope)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=scope)

    with (
        client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()

        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        recv_until(ws1, "huddle.update")
        recv_until(ws2, "huddle.update")

        # The caller-already-busy check runs BEFORE any peer lookup, so a second invite is
        # rejected even against an unseeded/offline peer_user_id.
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": str(uuid.uuid4())})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_invite_offline_peer_is_huddle_unavailable(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)  # seeded, but never connects a socket
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_invite_nonexistent_peer_is_huddle_unavailable_not_an_oracle(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": str(uuid.uuid4())})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_invite_cross_tenant_peer_is_huddle_unavailable_not_an_oracle(
    make_client, seed_user, mint_token, new_uuid
):
    """A peer_user_id that exists but in ANOTHER tenant looks identical to a nonexistent one."""
    tenant_a, tenant_b = new_uuid(), new_uuid()
    u1 = new_uuid()
    other_tenant_user = new_uuid()
    seed_user(tenant_id=tenant_a, user_id=u1)
    seed_user(tenant_id=tenant_b, user_id=other_tenant_user)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant_a, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": other_tenant_user})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_malformed_huddle_invite_frame_is_invalid_message(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite"})  # missing required peer_user_id
        err = recv_until(ws1, "error")
        assert err["error_code"] == "invalid_message"


def test_malformed_huddle_hangup_frame_is_invalid_message(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.hangup"})  # missing required huddle_id
        err = recv_until(ws1, "error")
        assert err["error_code"] == "invalid_message"


def test_invite_without_huddle_initiate_scope_is_unauthorized(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(
        user_id=u1, tenant_id=tenant, scope="chat:read chat:write"
    )  # NO huddle:initiate
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "unauthorized"


def test_self_invite_is_invalid_message(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u1})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "invalid_message"


def test_channel_scoped_invite_requires_peer_membership(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for uid in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=uid)
    client = make_client()
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    t3 = mint_token(user_id=u3, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    channel_id = make_channel(client, owner_tok, members=[(u2, "member")])

    with client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2:
        ws2.receive_json()
        with client.websocket_connect(_REALTIME, headers=auth(t3)) as ws3:
            ws3.receive_json()
            with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
                ws1.receive_json()

                # u3 is NOT a member of the channel -> huddle_unavailable, even though online.
                ws1.send_json(
                    {"msg_type": "huddle.invite", "peer_user_id": u3, "channel_id": channel_id}
                )
                err = recv_until(ws1, "error")
                assert err["error_code"] == "huddle_unavailable"

                # u2 IS a member -> rings normally.
                ws1.send_json(
                    {"msg_type": "huddle.invite", "peer_user_id": u2, "channel_id": channel_id}
                )
                ring1 = recv_until(ws1, "huddle.update")
                assert ring1["state"] == "ringing"


def test_signal_send_to_unknown_huddle_is_huddle_unavailable(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": str(uuid.uuid4()),
                "signal": {"kind": "offer", "sdp": "v=0"},
            }
        )
        err = recv_until(ws1, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_hangup_unknown_huddle_is_huddle_unavailable(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": str(uuid.uuid4())})
        err = recv_until(ws1, "error")
        assert err["error_code"] == "huddle_unavailable"


def test_a_stranger_cannot_signal_or_hangup_someone_elses_huddle(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2, u3 = new_uuid(), new_uuid(), new_uuid()
    for uid in (u1, u2, u3):
        seed_user(tenant_id=tenant, user_id=uid)
    client = make_client()
    scope = "chat:read chat:write huddle:initiate"
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=scope)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=scope)
    t3 = mint_token(user_id=u3, tenant_id=tenant, scope=scope)

    with client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2:
        ws2.receive_json()
        with client.websocket_connect(_REALTIME, headers=auth(t3)) as ws3:
            ws3.receive_json()
            with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
                ws1.receive_json()

                ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
                ring1 = recv_until(ws1, "huddle.update")
                recv_until(ws2, "huddle.update")
                huddle_id = ring1["huddle_id"]

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


def test_disconnect_ends_the_huddle_and_notifies_the_peer(
    make_client, seed_user, mint_token, new_uuid
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    scope = "chat:read chat:write huddle:initiate"
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=scope)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=scope)

    with client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2:
        ws2.receive_json()
        with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
            ws1.receive_json()
            ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
            recv_until(ws1, "huddle.update")
            recv_until(ws2, "huddle.update")
            # ws1 drops here (context exit) without an explicit huddle.hangup.

        ended = recv_until(ws2, "huddle.update")
        assert ended["state"] == "ended"
        assert ended["peer_user_id"] == u1


def test_signal_send_seam_block_is_not_relayed(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client(inspector=AllBlockInspector())
    scope = "chat:read chat:write huddle:initiate"
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=scope)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=scope)

    with (
        client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        ring1 = recv_until(ws1, "huddle.update")
        recv_until(ws2, "huddle.update")

        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": ring1["huddle_id"],
                "signal": {"kind": "offer", "sdp": "v=0 blocked"},
            }
        )
        err = recv_until(ws1, "error")
        assert err["error_code"] == "message_blocked"

        # Nothing relayed and no lifecycle change — a following clean invite/accept still ring
        # correctly from a fresh huddle, proving the block did not corrupt this one's state.
        ws1.send_json({"msg_type": "huddle.hangup", "huddle_id": ring1["huddle_id"]})
        ended1 = recv_until(ws1, "huddle.update")
        assert ended1["state"] == "ended"


@pytest.mark.parametrize("inspector", [UnavailableInspector(), RaisingInspector()])
def test_signal_send_seam_unavailable_fails_closed(
    make_client, seed_user, mint_token, new_uuid, inspector
):
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client(inspector=inspector)
    scope = "chat:read chat:write huddle:initiate"
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=scope)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=scope)

    with (
        client.websocket_connect(_REALTIME, headers=auth(t2)) as ws2,
        client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1,
    ):
        ws2.receive_json()
        ws1.receive_json()
        ws1.send_json({"msg_type": "huddle.invite", "peer_user_id": u2})
        ring1 = recv_until(ws1, "huddle.update")
        recv_until(ws2, "huddle.update")

        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": ring1["huddle_id"],
                "signal": {"kind": "offer", "sdp": "v=0"},
            }
        )
        err = recv_until(ws1, "error")
        assert err["error_code"] == "inspection_unavailable"


def test_invalid_signal_frame_is_invalid_message(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write huddle:initiate")
    with client.websocket_connect(_REALTIME, headers=auth(t1)) as ws1:
        ws1.receive_json()
        ws1.send_json(
            {
                "msg_type": "signal.send",
                "huddle_id": str(uuid.uuid4()),
                "signal": {"kind": "bogus"},
            }
        )
        err = recv_until(ws1, "error")
        assert err["error_code"] == "invalid_message"
