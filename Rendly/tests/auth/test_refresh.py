"""R-003 refresh flow — rotation, reuse-detection, revocation (FORK B+E)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from authdata import ALEX_PASSWORD, ALEX_USERNAME


def _login(client: TestClient) -> dict:
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": ALEX_USERNAME, "password": ALEX_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _refresh(client: TestClient, refresh_token: str):
    return client.post(
        "/v1/auth/token",
        json={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )


def test_refresh_grant_rotates_the_refresh_token(client: TestClient) -> None:
    first = _login(client)
    resp = _refresh(client, first["refresh_token"])
    assert resp.status_code == 200, resp.text
    rotated = resp.json()
    assert rotated["refresh_token"] != first["refresh_token"]  # rotated, not reused
    assert rotated["access_token"].count(".") == 2
    # The rotated access token still authorizes.
    me = client.get("/v1/users/me", headers={"Authorization": f"Bearer {rotated['access_token']}"})
    assert me.status_code == 200


def test_replayed_refresh_token_is_rejected(client: TestClient) -> None:
    first = _login(client)
    rt1 = first["refresh_token"]
    assert _refresh(client, rt1).status_code == 200  # legitimate rotation consumes rt1
    replay = _refresh(client, rt1)  # presenting rt1 again = reuse
    assert replay.status_code == 401
    assert replay.json()["error_code"] == "invalid_token"


def test_reuse_revokes_the_whole_family(client: TestClient) -> None:
    first = _login(client)
    rt1 = first["refresh_token"]
    rotated = _refresh(client, rt1).json()
    rt2 = rotated["refresh_token"]
    # Replay rt1 -> reuse-detection revokes the family...
    assert _refresh(client, rt1).status_code == 401
    # ...so the freshly-minted rt2 is now dead too.
    assert _refresh(client, rt2).status_code == 401


def test_revoke_makes_refresh_unusable(client: TestClient) -> None:
    first = _login(client)
    rt = first["refresh_token"]
    revoke = client.post("/v1/auth/revoke", json={"token": rt})
    assert revoke.status_code == 204
    assert revoke.headers["X-Request-Id"]
    assert _refresh(client, rt).status_code == 401


def test_revoke_is_idempotent(client: TestClient) -> None:
    rt = _login(client)["refresh_token"]
    assert client.post("/v1/auth/revoke", json={"token": rt}).status_code == 204
    # Revoking again still 204 (no token-existence leak).
    assert client.post("/v1/auth/revoke", json={"token": rt}).status_code == 204


def test_revoke_unknown_token_is_204(client: TestClient) -> None:
    resp = client.post("/v1/auth/revoke", json={"token": "rt_does_not_exist"})
    assert resp.status_code == 204
