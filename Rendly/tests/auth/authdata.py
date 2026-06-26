"""Shared constants + token helpers for the auth suite (plain importable module).

Kept out of conftest.py so the test modules can import these by name (pytest puts this directory
on sys.path); conftest holds only auto-injected fixtures. Nothing here is a real credential — the
fixture passwords are obvious non-secrets matching ``rendly.auth.store.build_fixture_store``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

# Known fixture credentials (see rendly.auth.store.build_fixture_store).
ALEX_USERNAME = "alex@tenant-a.example"
ALEX_PASSWORD = "alex-fixture-pw"
ALEX_USER_ID = "7d9e2f3a-1234-5c6b-8def-0123456789ab"
TENANT_A = "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6"
KIM_USERNAME = "kim@tenant-b.example"
KIM_PASSWORD = "kim-fixture-pw"
TENANT_B = "9f8e7d6c-1122-4a3b-8c9d-e0f1a2b3c4d5"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def none_alg_token(payload: dict) -> str:
    """Hand-craft an unsigned ``alg:none`` token (PyJWT refuses to emit one)."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    return f"{header}.{_b64url(json.dumps(payload).encode())}."


def hs256_token_with_secret(payload: dict, secret: str) -> str:
    """Hand-craft an HS256 token signed with ``secret`` as the HMAC key.

    PyJWT's ``encode`` refuses to use an asymmetric public key as an HMAC secret (its own
    guard), so the classic alg-confusion forgery is built by hand. Used to prove the SERVER
    rejects an HS256-alg token outright (its ``algorithms=["ES256"]`` allowlist), independent of
    whether the signature would have matched.
    """
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"
