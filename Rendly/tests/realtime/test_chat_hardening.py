"""R-005 hardening — the fixes from the independent code-review + security-audit.

Covers: the contracted internal_error frame on an unhandled handler error (so a DB outage notifies
the client instead of silently closing the socket), live registry eviction when a member is
removed (a revoked member's open socket stops receiving), and the pre-parse WS frame size cap.
"""

from __future__ import annotations

from chatdata import auth, make_channel, recv_until

_REALTIME = "/v1/realtime"
_FULL = "channels:write channels:admin chat:read chat:write"


def test_handler_exception_yields_internal_error_frame(
    make_client, seed_user, mint_token, new_uuid, monkeypatch
):
    """An unhandled error in a frame handler (e.g. DB outage mid-persist) sends internal_error,
    keeps the socket up, and never persists/delivers (fail-closed)."""
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    owner = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    u1_tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    make_channel(client, owner)  # u1 sole member

    # Force the persist to raise AFTER the pre-check + inspection have passed.
    import rendly.persistence.chat_repo as cr

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("db exploded mid-persist")

    monkeypatch.setattr(cr, "insert_message", _boom)

    cid = client.post(
        "/v1/channels", json={"name": "x", "type": "private"}, headers=auth(owner)
    ).json()["channel_id"]

    with client.websocket_connect(_REALTIME, headers=auth(u1_tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_json(
            {"msg_type": "chat.send", "client_msg_id": "c-boom", "channel_id": cid, "content": "hi"}
        )
        assert recv_until(ws, "error")["error_code"] == "internal_error"
        # The socket survived the handler error: a following frame is still served.
        ws.send_text("not json")
        assert recv_until(ws, "error")["error_code"] == "invalid_message"


def test_removed_member_is_evicted_from_live_registry(make_client, seed_user, mint_token, new_uuid):
    """DELETE member evicts the member's live connection from the channel bucket immediately."""
    tenant, u1, u2 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    owner = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    u2_tok = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read")
    cid = make_channel(client, owner, members=[(u2, "member")])

    with client.websocket_connect(_REALTIME, headers=auth(u2_tok)) as ws2:
        assert ws2.receive_json()["msg_type"] == "session.welcome"
        registry = client.app.state.realtime_ctx.registry
        # u2's connection is in the channel bucket while connected + a member.
        assert any(c.user_id == u2 for c in registry.channel_connections(tenant, cid))

        # Owner removes u2.
        assert (
            client.delete(f"/v1/channels/{cid}/members/{u2}", headers=auth(owner)).status_code
            == 204
        )

        # u2's connection is no longer in the channel bucket -> it will not receive new fan-out.
        assert not any(c.user_id == u2 for c in registry.channel_connections(tenant, cid))


def test_oversized_frame_rejected_before_parse(make_client, seed_user, mint_token, new_uuid):
    """A raw frame over the size cap is rejected (message_too_large) before json.loads runs."""
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    with client.websocket_connect(_REALTIME, headers=auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        ws.send_text("x" * 70000)  # > MAX_FRAME_BYTES (65536); not even valid JSON
        assert recv_until(ws, "error")["error_code"] == "message_too_large"
