"""R-005 minimal chat REST — channel create, member upsert/remove, keyset history.

Exercises the contract-locked REST surface end-to-end on real Postgres via the in-process app,
including the closed-schema + scope + 404-no-oracle behaviors.
"""

from __future__ import annotations

from sqlalchemy import text

_FULL = "channels:write channels:admin chat:read chat:write"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _owner_membership(tenant_id: str, channel_id: str, user_id: str):
    from rendly.persistence.database import get_privileged_session

    with get_privileged_session() as s:
        return (
            s.execute(
                text(
                    "SELECT role FROM rendly.memberships "
                    "WHERE tenant_id=:t AND channel_id=:c AND user_id=:u"
                ),
                {"t": tenant_id, "c": channel_id, "u": user_id},
            )
            .scalars()
            .first()
        )


def test_create_channel_makes_creator_owner(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    resp = client.post("/v1/channels", json={"name": "eng", "type": "private"}, headers=_auth(tok))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["tenant_id"] == tenant
    assert body["created_by"] == u1
    assert body["source"] == "manual"
    assert body["external_ref"] is None
    assert body["archived"] is False
    assert _owner_membership(tenant, body["channel_id"], u1) == "owner"


def test_create_channel_rejects_client_supplied_external_ref(
    make_client, seed_user, mint_token, new_uuid
):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    # The Delta-mapping pointer is server-managed; a client-supplied one is rejected (closed schema).
    resp = client.post(
        "/v1/channels",
        json={"name": "eng", "type": "private", "external_ref": "delta:team:1"},
        headers=_auth(tok),
    )
    assert resp.status_code == 400


def test_create_channel_requires_channels_write_scope(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(
        user_id=u1, tenant_id=tenant, scope="chat:read chat:write"
    )  # no channels:write
    resp = client.post("/v1/channels", json={"name": "eng", "type": "private"}, headers=_auth(tok))
    assert resp.status_code == 403


def test_member_add_then_remove_is_idempotent(make_client, seed_user, mint_token, new_uuid):
    tenant, u1, u2 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    cid = client.post(
        "/v1/channels", json={"name": "c", "type": "private"}, headers=_auth(tok)
    ).json()["channel_id"]

    add = client.put(
        f"/v1/channels/{cid}/members/{u2}", json={"role": "member"}, headers=_auth(tok)
    )
    assert add.status_code == 200
    assert add.json()["user_id"] == u2
    assert add.json()["role"] == "member"

    # Idempotent role change (delete+insert under the hood).
    again = client.put(
        f"/v1/channels/{cid}/members/{u2}", json={"role": "admin"}, headers=_auth(tok)
    )
    assert again.status_code == 200
    assert again.json()["role"] == "admin"

    rm = client.delete(f"/v1/channels/{cid}/members/{u2}", headers=_auth(tok))
    assert rm.status_code == 204
    rm_again = client.delete(f"/v1/channels/{cid}/members/{u2}", headers=_auth(tok))
    assert rm_again.status_code == 204  # idempotent


def test_member_ops_to_foreign_tenant_user_is_404(make_client, seed_user, mint_token, new_uuid):
    """Adding a user that is not in the caller's tenant resolves as 404 (no cross-tenant oracle)."""
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)  # ub exists, but in tenant B
    client = make_client()
    tok = mint_token(user_id=ua, tenant_id=ta, scope=_FULL)
    cid = client.post(
        "/v1/channels", json={"name": "c", "type": "private"}, headers=_auth(tok)
    ).json()["channel_id"]
    resp = client.put(
        f"/v1/channels/{cid}/members/{ub}", json={"role": "member"}, headers=_auth(tok)
    )
    assert resp.status_code == 404


def test_message_history_keyset_pagination(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    cid = client.post(
        "/v1/channels", json={"name": "c", "type": "private"}, headers=_auth(tok)
    ).json()["channel_id"]

    # Send 3 messages over the real WS so seq is assigned by the live send path.
    with client.websocket_connect("/v1/realtime", headers=_auth(tok)) as ws:
        assert ws.receive_json()["msg_type"] == "session.welcome"
        for i in range(3):
            ws.send_json(
                {
                    "msg_type": "chat.send",
                    "client_msg_id": f"c-{i}",
                    "channel_id": cid,
                    "content": f"m{i}",
                }
            )
            # drain the ack (and the self-delivered message) so the next send is clean
            seen_ack = False
            while not seen_ack:
                frame = ws.receive_json()
                if frame.get("msg_type") == "chat.ack":
                    assert frame["status"] == "accepted"
                    seen_ack = True

    # Page 1: newest first, limit 2 -> m2 (seq 2), m1 (seq 1); cursor points past seq 1.
    page1 = client.get(f"/v1/channels/{cid}/messages?limit=2", headers=_auth(tok)).json()
    assert [m["content"] for m in page1["messages"]] == ["m2", "m1"]
    assert page1["messages"][0]["archival"]["seq"] == 2
    assert page1["messages"][0]["inspection"]["status"] == "pass"
    assert page1["messages"][0]["archival"]["prev_record_hash"] is None
    assert page1["next_cursor"] == "1"

    # Page 2: the remaining oldest message.
    page2 = client.get(
        f"/v1/channels/{cid}/messages?limit=2&cursor={page1['next_cursor']}", headers=_auth(tok)
    ).json()
    assert [m["content"] for m in page2["messages"]] == ["m0"]
    assert page2["next_cursor"] is None


def test_history_requires_membership(make_client, seed_user, mint_token, new_uuid):
    """A non-member reading history gets 404 (same as a non-existent channel — no oracle)."""
    tenant, u1, u2 = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    owner_tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    cid = client.post(
        "/v1/channels", json={"name": "c", "type": "private"}, headers=_auth(owner_tok)
    ).json()["channel_id"]
    # u2 is a tenant member but NOT a channel member.
    u2_tok = mint_token(user_id=u2, tenant_id=tenant, scope="chat:read")
    resp = client.get(f"/v1/channels/{cid}/messages", headers=_auth(u2_tok))
    assert resp.status_code == 404


def test_history_bad_cursor_is_400(make_client, seed_user, mint_token, new_uuid):
    tenant, u1 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL)
    cid = client.post(
        "/v1/channels", json={"name": "c", "type": "private"}, headers=_auth(tok)
    ).json()["channel_id"]
    resp = client.get(f"/v1/channels/{cid}/messages?cursor=not-an-int", headers=_auth(tok))
    assert resp.status_code == 400
