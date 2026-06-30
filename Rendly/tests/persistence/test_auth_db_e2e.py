"""R-004 auth e2e on the DB store — R-003's full token path against REAL Postgres.

The R-003 honesty boundary ("only the user lookup is fixture-backed") is RETIRED here: the
credential lookup, the identity fetch, AND the refresh-token state are all real Postgres.
Proves password-grant -> access+refresh, refresh-rotate, and that replaying a USED refresh
token revokes the family and the next rotate fails (RefreshReuse -> 401) — across a FRESH
connection (engines reset between issue and replay), not just in-process.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from rendly.auth.keys import KeyMaterial, load_key_material
from rendly.enums import OrgRole
from rendly.persistence.database import reset_engines
from rendly.persistence.identity_app import create_db_app

T_A = "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6"
U_A = "7d9e2f3a-1234-5c6b-8def-0123456789ab"
USERNAME = "alex@tenant-a.example"
PASSWORD = "alex-db-fixture-pw"


@pytest.fixture(scope="session")
def key() -> KeyMaterial:
    """A real ES256 (P-256) key loaded through the production fail-closed loader."""
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    return load_key_material(pem)


@pytest.fixture
def client(key: KeyMaterial, seed_identity) -> TestClient:
    """TestClient over the DB-backed app, with one seeded user in tenant A."""
    seed_identity(
        tenant_id=T_A,
        user_id=U_A,
        username=USERNAME,
        password=PASSWORD,
        org_role=OrgRole.MEMBER,
        team="platform",
        display_name="Alex Rivera",
    )
    return TestClient(create_db_app(key=key))


def _password_grant(client: TestClient) -> dict:
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": USERNAME, "password": PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_password_grant_against_db(client: TestClient) -> None:
    tokens = _password_grant(client)
    assert tokens["token_type"] == "Bearer"
    assert tokens["access_token"].count(".") == 2
    assert tokens["refresh_token"].startswith("rt_")
    assert "profile:read" in tokens["scope"].split()


def test_users_me_authorizes_against_db(client: TestClient) -> None:
    access = _password_grant(client)["access_token"]
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user_id"] == U_A
    assert body["tenant_id"] == T_A
    assert body["display_name"] == "Alex Rivera"


def test_bad_password_is_generic_401_against_db(client: TestClient) -> None:
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": USERNAME, "password": "wrong"},
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_unknown_user_is_same_generic_401_against_db(client: TestClient) -> None:
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": "nobody@x.example", "password": "x"},
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_refresh_rotate_against_db(client: TestClient) -> None:
    first = _password_grant(client)
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
    )
    assert resp.status_code == 200, resp.text
    rotated = resp.json()
    assert rotated["refresh_token"].startswith("rt_")
    assert rotated["refresh_token"] != first["refresh_token"]


def test_refresh_reuse_revokes_family_across_fresh_connection(client: TestClient) -> None:
    first = _password_grant(client)
    original = first["refresh_token"]

    # Legitimate rotation -> the original is now consumed (used=True), a successor minted.
    r1 = client.post(
        "/v1/auth/token",
        json={"grant_type": "refresh_token", "refresh_token": original},
    )
    assert r1.status_code == 200, r1.text
    successor = r1.json()["refresh_token"]

    # Drop the pool so the replay runs over a brand-new connection — the reuse-detection
    # must rely on PERSISTED state, not in-process memory.
    reset_engines()

    # Replay the already-used original: reuse detected -> family revoked -> 401.
    replay = client.post(
        "/v1/auth/token",
        json={"grant_type": "refresh_token", "refresh_token": original},
    )
    assert replay.status_code == 401
    assert replay.json()["error_code"] == "invalid_token"

    # The successor was valid a moment ago, but the family is now revoked -> also 401.
    after = client.post(
        "/v1/auth/token",
        json={"grant_type": "refresh_token", "refresh_token": successor},
    )
    assert after.status_code == 401
    assert after.json()["error_code"] == "invalid_token"


def test_revoke_is_idempotent_and_blocks_future_rotate(client: TestClient) -> None:
    first = _password_grant(client)
    token = first["refresh_token"]

    # Revoke (logout) twice — idempotent, both 204.
    for _ in range(2):
        resp = client.post("/v1/auth/revoke", json={"token": token})
        assert resp.status_code == 204

    reset_engines()
    # Rotating a revoked-family token now fails.
    resp = client.post(
        "/v1/auth/token", json={"grant_type": "refresh_token", "refresh_token": token}
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"

    # Revoking an entirely unknown token is also a silent no-op (204).
    resp = client.post("/v1/auth/revoke", json={"token": "rt_does-not-exist"})
    assert resp.status_code == 204
