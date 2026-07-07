"""R-007 ``GET /v1/huddles/ice-servers`` — the self-hosted ICE/TURN bootstrap REST endpoint."""

from __future__ import annotations

from chatdata import auth


def test_ice_servers_requires_huddle_initiate_scope(make_client, seed_user, mint_token, new_uuid):
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read")  # no huddle:initiate
    resp = client.get("/v1/huddles/ice-servers", headers=auth(tok))
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "forbidden"


def test_ice_servers_rejects_unauthenticated(make_client):
    client = make_client()
    resp = client.get("/v1/huddles/ice-servers")
    assert resp.status_code == 401


def test_ice_servers_defaults_to_no_servers_when_unconfigured(
    make_client, seed_user, mint_token, new_uuid
):
    """No env-configured STUN/TURN -> an empty (never fabricated) ice_servers list."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="huddle:initiate")
    resp = client.get("/v1/huddles/ice-servers", headers=auth(tok))
    assert resp.status_code == 200
    body = resp.json()
    assert body["ice_servers"] == []
    assert 1 <= body["ttl_seconds"] <= 86400


def test_ice_servers_returns_configured_stun_and_turn(make_client, seed_user, mint_token, new_uuid):
    from rendly.realtime.ice import IceServerConfig

    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    config = IceServerConfig(
        stun_urls=("stun:turn.rendly.internal:3478",),
        turn_urls=("turn:turn.rendly.internal:3478?transport=udp",),
        turn_secret="topsecret",
        ttl_seconds=300,
    )
    client = make_client(ice_config=config)
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="huddle:initiate")
    resp = client.get("/v1/huddles/ice-servers", headers=auth(tok))
    assert resp.status_code == 200
    body = resp.json()
    assert body["ttl_seconds"] == 300
    assert len(body["ice_servers"]) == 2
    stun_entry = next(e for e in body["ice_servers"] if e["username"] is None)
    turn_entry = next(e for e in body["ice_servers"] if e["username"] is not None)
    assert stun_entry["urls"] == ["stun:turn.rendly.internal:3478"]
    assert turn_entry["urls"] == ["turn:turn.rendly.internal:3478?transport=udp"]
    assert turn_entry["credential"]  # a short-lived HMAC credential, never a fixed secret


def test_ice_servers_never_returns_an_external_meeting_link(
    make_client, seed_user, mint_token, new_uuid
):
    """Honesty-boundary regression: only operator-configured self-hosted endpoints are ever
    returned, never a hardcoded/fabricated third-party (Zoom/Meet/Twilio) URL."""
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="huddle:initiate")
    resp = client.get("/v1/huddles/ice-servers", headers=auth(tok))
    body = resp.json()
    for entry in body["ice_servers"]:
        for url in entry["urls"]:
            assert url.startswith(("stun:", "turn:", "turns:"))
