"""R-003 adversarial — alg-confusion / none-alg, claim-injection, cross-tenant.

These are the security-relevant attacks the dispatch + R-001 audit call out. Each must fail
closed. The crafted-token tests sign with the server's own key (only the server holds it), so they
prove the verification logic rejects the malformed shape — not that an outsider could forge one.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable

import jwt
from fastapi.testclient import TestClient

from rendly.app import create_app
from rendly.auth.keys import KeyMaterial
from rendly.auth.refresh import InMemoryRefreshTokenStore
from rendly.auth.store import UserStore, build_fixture_store
from rendly.user import User

from authdata import (
    ALEX_PASSWORD,
    ALEX_USER_ID,
    ALEX_USERNAME,
    KIM_PASSWORD,
    KIM_USERNAME,
    TENANT_A,
    TENANT_B,
    hs256_token_with_secret,
    none_alg_token,
)


def _claims(**over: object) -> dict:
    now = int(time.time())
    base = {
        "iss": "https://rendly.anoryx.io",
        "sub": ALEX_USER_ID,
        "tenant_id": TENANT_A,
        "scope": "profile:read",
        "token_use": "access",
        "iat": now,
        "exp": now + 900,
        "jti": "adv-jti",
        "roles": ["member"],
        "idp_subject": None,
    }
    base.update(over)
    return base


def _decode_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def test_alg_none_token_is_rejected(client: TestClient) -> None:
    token = none_alg_token(_claims())
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_alg_confusion_hs256_with_public_key_is_rejected(
    client: TestClient, public_pem: str
) -> None:
    # Classic confusion: forge an HS256 token using the ES256 PUBLIC key as the HMAC secret.
    # The server's algorithms=["ES256"] allowlist rejects the HS256 alg before any key use.
    forged = hs256_token_with_secret(_claims(), public_pem)
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_request_body_cannot_inject_tenant_id(client: TestClient) -> None:
    # The closed TokenRequest rejects an unknown key -> 400, never silently honored.
    resp = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "password",
            "username": ALEX_USERNAME,
            "password": ALEX_PASSWORD,
            "tenant_id": TENANT_B,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


def test_issued_tenant_is_token_derived_not_request_derived(client: TestClient) -> None:
    resp = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": ALEX_USERNAME, "password": ALEX_PASSWORD},
    )
    access = resp.json()["access_token"]
    # The tenant_id in the token is alex's own, resolved server-side — not anything client-supplied.
    assert _decode_payload(access)["tenant_id"] == TENANT_A


def test_cross_tenant_principal_cannot_resolve_a_foreign_user(
    client: TestClient, sign_raw: Callable[..., str]
) -> None:
    # A (signed) token claiming alex's user_id under a DIFFERENT tenant resolves no user -> 401.
    token = sign_raw(_claims(tenant_id=TENANT_B))
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_token"


def test_each_token_sees_only_its_own_tenant_user(client: TestClient) -> None:
    kim = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": KIM_USERNAME, "password": KIM_PASSWORD},
    ).json()
    me = client.get("/v1/users/me", headers={"Authorization": f"Bearer {kim['access_token']}"})
    assert me.status_code == 200
    body = me.json()
    assert body["tenant_id"] == TENANT_B
    assert body["user_id"] != ALEX_USER_ID


def test_a_real_verify_still_accepts_a_genuine_token(client: TestClient, key: object) -> None:
    # Control: the same verify path that rejects the forgeries accepts a server-signed token.
    genuine = jwt.encode(_claims(), key.private_key, algorithm="ES256")  # type: ignore[attr-defined]
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {genuine}"})
    assert resp.status_code == 200


class _BoomUserStore(UserStore):
    """Issues fine (get_credentials), but raises on the identity lookup — to test fail-closed."""

    def __init__(self) -> None:
        self._inner = build_fixture_store()

    def get_credentials(self, username: str):
        return self._inner.get_credentials(username)

    def get_user(self, user_id: str, tenant_id: str) -> User | None:
        raise RuntimeError("simulated internal failure")


def test_internal_error_fails_closed_to_500(key: KeyMaterial) -> None:
    # Any unexpected error must fail closed to 500 internal_error — never pass traffic through.
    app = create_app(
        user_store=_BoomUserStore(), refresh_store=InMemoryRefreshTokenStore(), key=key
    )
    client = TestClient(app, raise_server_exceptions=False)
    access = client.post(
        "/v1/auth/token",
        json={"grant_type": "password", "username": ALEX_USERNAME, "password": ALEX_PASSWORD},
    ).json()["access_token"]
    resp = client.get("/v1/users/me", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"
    assert resp.headers["X-Request-Id"]
