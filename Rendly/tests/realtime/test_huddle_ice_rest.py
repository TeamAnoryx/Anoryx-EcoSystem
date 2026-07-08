"""R-007 ``GET /v1/huddles/ice-servers`` — the self-hosted ICE/TURN bootstrap (realtime/ice.py).

Exercises the REAL FastAPI route over the real chat app (no DB involvement — the endpoint reads
only the verified token + env config), and separately unit-tests the TURN credential scheme.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

_FULL_SCOPE = "chat:read chat:write huddle:initiate"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_requires_huddle_initiate_scope(make_client, seed_user, mint_token, new_uuid, monkeypatch):
    monkeypatch.delenv("RENDLY_STUN_URLS", raising=False)
    monkeypatch.delenv("RENDLY_TURN_URLS", raising=False)
    monkeypatch.delenv("RENDLY_TURN_SHARED_SECRET", raising=False)
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope="chat:read chat:write")
    resp = client.get("/v1/huddles/ice-servers", headers=_auth(tok))
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "forbidden"


def test_defaults_to_empty_ice_servers_without_config(
    make_client, seed_user, mint_token, new_uuid, monkeypatch
):
    monkeypatch.delenv("RENDLY_STUN_URLS", raising=False)
    monkeypatch.delenv("RENDLY_TURN_URLS", raising=False)
    monkeypatch.delenv("RENDLY_TURN_SHARED_SECRET", raising=False)
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    resp = client.get("/v1/huddles/ice-servers", headers=_auth(tok))
    assert resp.status_code == 200
    body = resp.json()
    assert body["ice_servers"] == []
    assert body["ttl_seconds"] == 600


def test_stun_only_needs_no_credential(make_client, seed_user, mint_token, new_uuid, monkeypatch):
    monkeypatch.setenv("RENDLY_STUN_URLS", "stun:turn.rendly.anoryx.io:3478")
    monkeypatch.delenv("RENDLY_TURN_URLS", raising=False)
    monkeypatch.delenv("RENDLY_TURN_SHARED_SECRET", raising=False)
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    resp = client.get("/v1/huddles/ice-servers", headers=_auth(tok))
    assert resp.status_code == 200
    servers = resp.json()["ice_servers"]
    assert servers == [
        {"urls": ["stun:turn.rendly.anoryx.io:3478"], "username": None, "credential": None}
    ]


def test_turn_without_shared_secret_is_dropped_fail_closed(
    make_client, seed_user, mint_token, new_uuid, monkeypatch
):
    monkeypatch.delenv("RENDLY_STUN_URLS", raising=False)
    monkeypatch.setenv("RENDLY_TURN_URLS", "turn:turn.rendly.anoryx.io:3478?transport=udp")
    monkeypatch.delenv("RENDLY_TURN_SHARED_SECRET", raising=False)
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    resp = client.get("/v1/huddles/ice-servers", headers=_auth(tok))
    assert resp.status_code == 200
    assert resp.json()["ice_servers"] == []


def test_turn_with_shared_secret_mints_a_verifiable_short_lived_credential(
    make_client, seed_user, mint_token, new_uuid, monkeypatch
):
    monkeypatch.setenv("RENDLY_STUN_URLS", "stun:turn.rendly.anoryx.io:3478")
    monkeypatch.setenv("RENDLY_TURN_URLS", "turn:turn.rendly.anoryx.io:3478?transport=udp")
    monkeypatch.setenv("RENDLY_TURN_SHARED_SECRET", "top-secret-shared-key")
    tenant = new_uuid()
    u1 = new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    client = make_client()
    tok = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    resp = client.get("/v1/huddles/ice-servers", headers=_auth(tok))
    assert resp.status_code == 200
    body = resp.json()
    assert body["ttl_seconds"] == 600
    servers = body["ice_servers"]
    assert len(servers) == 2
    stun, turn = servers
    assert stun["username"] is None and stun["credential"] is None

    assert turn["urls"] == ["turn:turn.rendly.anoryx.io:3478?transport=udp"]
    username = turn["username"]
    expiry_str, _, embedded_user_id = username.partition(":")
    assert expiry_str.isdigit()
    assert embedded_user_id == u1  # opaque surrogate, never PII (ADR-0001 D6)

    expected = base64.b64encode(
        hmac.new(b"top-secret-shared-key", username.encode(), hashlib.sha1).digest()
    ).decode("ascii")
    assert turn["credential"] == expected


def test_ice_servers_response_is_tenant_and_user_scoped_per_caller(
    make_client, seed_user, mint_token, new_uuid, monkeypatch
):
    """Two different users get two DIFFERENT TURN credentials (each embeds its own user_id)."""
    monkeypatch.delenv("RENDLY_STUN_URLS", raising=False)
    monkeypatch.setenv("RENDLY_TURN_URLS", "turn:turn.rendly.anoryx.io:3478?transport=udp")
    monkeypatch.setenv("RENDLY_TURN_SHARED_SECRET", "top-secret-shared-key")
    tenant = new_uuid()
    u1, u2 = new_uuid(), new_uuid()
    seed_user(tenant_id=tenant, user_id=u1)
    seed_user(tenant_id=tenant, user_id=u2)
    client = make_client()
    t1 = mint_token(user_id=u1, tenant_id=tenant, scope=_FULL_SCOPE)
    t2 = mint_token(user_id=u2, tenant_id=tenant, scope=_FULL_SCOPE)
    r1 = client.get("/v1/huddles/ice-servers", headers=_auth(t1)).json()
    r2 = client.get("/v1/huddles/ice-servers", headers=_auth(t2)).json()
    assert r1["ice_servers"][0]["credential"] != r2["ice_servers"][0]["credential"]
