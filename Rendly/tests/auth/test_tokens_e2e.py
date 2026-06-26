"""R-003 e2e — the REAL token path against the fixture store.

Proves: valid creds -> real ES256 token issued -> verify dependency verifies -> request
authorized. Plus the fail-closed 401 paths (expired, tampered, wrong issuer, wrong token_use,
missing). Only the user lookup is fixture-backed; the crypto + verify are real.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi.testclient import TestClient

from authdata import ALEX_PASSWORD, ALEX_USER_ID, ALEX_USERNAME, TENANT_A


def _password_grant(client: TestClient, scope: str | None = None) -> dict:
    body: dict = {"grant_type": "password", "username": ALEX_USERNAME, "password": ALEX_PASSWORD}
    if scope is not None:
        body["scope"] = scope
    resp = client.post("/v1/auth/token", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _base_claims() -> dict:
    now = int(time.time())
    return {
        "iss": "https://rendly.anoryx.io",
        "sub": ALEX_USER_ID,
        "tenant_id": TENANT_A,
        "scope": "profile:read",
        "token_use": "access",
        "iat": now,
        "exp": now + 900,
        "jti": "test-jti-abc",
        "roles": ["member"],
        "idp_subject": None,
    }


def test_password_grant_issues_a_real_signed_token(client: TestClient) -> None:
    tokens = _password_grant(client)
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == 900
    assert tokens["access_token"].count(".") == 2  # a real compact JWS
    assert tokens["refresh_token"].startswith("rt_")
    assert "profile:read" in tokens["scope"].split()


def test_valid_token_authorizes_users_me(client: TestClient) -> None:
    access = _password_grant(client)["access_token"]
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user_id"] == ALEX_USER_ID
    assert body["tenant_id"] == TENANT_A
    assert body["display_name"] == "Alex Rivera"


def test_missing_token_is_401(client: TestClient) -> None:
    resp = client.get("/v1/users/me")
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"
    assert resp.headers["X-Request-Id"]


def test_expired_token_is_401(client: TestClient, sign_raw: Callable[..., str]) -> None:
    claims = _base_claims()
    now = int(time.time())
    claims["iat"] = now - 4000
    claims["exp"] = now - 1000  # already expired
    token = sign_raw(claims)
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_tampered_signature_is_401(client: TestClient) -> None:
    access = _password_grant(client)["access_token"]
    header, payload, signature = access.split(".")
    # Flip a HIGH-ORDER signature char so the decoded bytes are guaranteed to change.
    flipped = ("B" if signature[0] != "B" else "C") + signature[1:]
    tampered = f"{header}.{payload}.{flipped}"
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_wrong_issuer_is_401(client: TestClient, sign_raw: Callable[..., str]) -> None:
    claims = _base_claims()
    claims["iss"] = "https://evil.example"
    token = sign_raw(claims)
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_wrong_token_use_is_401(client: TestClient, sign_raw: Callable[..., str]) -> None:
    # S1: token_use replaces an audience check — a non-"access" token_use must be rejected.
    claims = _base_claims()
    claims["token_use"] = "refresh"
    token = sign_raw(claims)
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_insufficient_scope_is_403(client: TestClient, sign_raw: Callable[..., str]) -> None:
    # A valid token lacking profile:read cannot reach GET /users/me.
    claims = _base_claims()
    claims["scope"] = "chat:read"
    token = sign_raw(claims)
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "forbidden"


def test_bearer_scheme_required(client: TestClient) -> None:
    access = _password_grant(client)["access_token"]
    # Right token, wrong scheme -> still 401 (no non-Bearer acceptance).
    resp = client.get("/v1/users/me", headers={"Authorization": access})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_bad_password_is_generic_401(client: TestClient) -> None:
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": ALEX_USERNAME, "password": "wrong"},
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_unknown_user_is_same_generic_401(client: TestClient) -> None:
    # No user-enumeration: unknown username yields the SAME error as a wrong password.
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": "nobody@x.example", "password": "x"},
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_scope_subset_is_honored(client: TestClient) -> None:
    tokens = _password_grant(client, scope="profile:read")
    assert tokens["scope"] == "profile:read"  # down-scoped to the requested subset


def test_empty_password_is_400(client: TestClient) -> None:
    resp = client.post("/v1/auth/token", json={"grant_type": "password", "username": ALEX_USERNAME})
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


def test_refresh_grant_without_token_is_400(client: TestClient) -> None:
    resp = client.post("/v1/auth/token", json={"grant_type": "refresh_token"})
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


def test_empty_bearer_value_is_401(client: TestClient) -> None:
    resp = client.get("/v1/users/me", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_oversized_body_is_413(client: TestClient) -> None:
    # Fail-safe sizing: the body cap is enforced from Content-Length BEFORE parsing.
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": "a" * 70000, "password": "x"},
    )
    assert resp.status_code == 413
    assert resp.json()["error_code"] == "request_too_large"


def test_body_without_content_length_fails_closed_413(client: TestClient) -> None:
    # A streamed body (chunked Transfer-Encoding, no Content-Length) must fail CLOSED, not bypass
    # the cap. Passing an iterator makes httpx use chunked encoding with no Content-Length header.
    resp = client.post("/v1/auth/token", content=iter([b'{"grant_type":"password"}']))
    assert resp.status_code == 413
    assert resp.json()["error_code"] == "request_too_large"


def test_requesting_ungranted_scope_is_400(client: TestClient) -> None:
    # A guest-only token request asking for an admin scope is a widening attempt -> rejected.
    resp = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "password",
            "username": ALEX_USERNAME,
            "password": ALEX_PASSWORD,
            "scope": "channels:admin",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"
