"""Operator-session token unit tests (F-014 STEP 7, ADR-0017 §3 D2 / §9 D8).

PURE-UNIT (no DB): mint/verify operate on an env secret only. These prove the
auth-boundary token mechanics:
  * mint -> verify round-trip returns the exact claims (tenant-pin + role + actor).
  * an expired token is rejected (exp <= now).
  * a tampered signature is rejected (constant-time compare).
  * a tampered payload (re-pinning to another tenant) is rejected (sig mismatch).
  * a token minted under a DIFFERENT secret is rejected (wrong-secret).
  * an UNSET secret fails closed: both mint and verify raise OperatorSessionError.

R6: the test secret is a runtime-assembled dummy (never a real secret); the token
is never logged.
"""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from admin.sso.session import (
    SESSION_TTL_SECONDS,
    OperatorSession,
    OperatorSessionError,
    mint,
    reset_secret_cache_for_testing,
    verify,
)

_SECRET = "unit-session-secret-" + "y" * 24  # noqa: S105 — test-only dummy
_OTHER_SECRET = "unit-other-secret-" + "z" * 24  # noqa: S105 — test-only dummy
_ENV = "SENTINEL_ADMIN_SESSION_SECRET"


def _principal(tenant_id="t-aaaa", role="tenant_admin", admin_user_id="u-1111"):
    return SimpleNamespace(tenant_id=tenant_id, admin_user_id=admin_user_id, role=role)


def _set_secret(monkeypatch, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv(_ENV, raising=False)
    else:
        monkeypatch.setenv(_ENV, value)
    reset_secret_cache_for_testing()


@pytest.fixture(autouse=True)
def _reset_cache():
    """Reset the load-once secret cache before and after every test."""
    reset_secret_cache_for_testing()
    yield
    reset_secret_cache_for_testing()


def test_mint_verify_round_trip(monkeypatch):
    """mint -> verify returns the exact tenant-pin + role + actor claims."""
    _set_secret(monkeypatch, _SECRET)
    token = mint(_principal(tenant_id="tenant-A", role="tenant_admin", admin_user_id="op-9"))
    claims = verify(token)
    assert isinstance(claims, OperatorSession)
    assert claims.tenant_id == "tenant-A"
    assert claims.role == "tenant_admin"
    assert claims.admin_user_id == "op-9"
    assert claims.auth_method == "sso"
    assert claims.exp - claims.iat == SESSION_TTL_SECONDS


def test_ttl_bounded_to_30_min(monkeypatch):
    """The TTL is <= 30 minutes (matches the cookie spine, ADR-0017 §3 D2.1)."""
    _set_secret(monkeypatch, _SECRET)
    assert SESSION_TTL_SECONDS <= 30 * 60
    token = mint(_principal(), now=1_000)
    claims = verify(token, now=1_000)
    assert claims.iat == 1_000
    assert claims.exp == 1_000 + SESSION_TTL_SECONDS


def test_expired_token_rejected(monkeypatch):
    """A token whose exp is at/before now is rejected (fail-closed, R4)."""
    _set_secret(monkeypatch, _SECRET)
    token = mint(_principal(), now=1_000)
    with pytest.raises(OperatorSessionError):
        verify(token, now=1_000 + SESSION_TTL_SECONDS)  # exactly expired
    with pytest.raises(OperatorSessionError):
        verify(token, now=1_000 + SESSION_TTL_SECONDS + 10)


def test_invalid_time_window_rejected(monkeypatch):
    """A token whose exp <= iat is rejected even when correctly signed + unexpired
    (F-014 code-review MED 1: reject a nonsensical time window before the expiry
    check). The payload is re-signed under the real secret so it clears the
    signature gate and exercises the exp<=iat guard specifically."""
    import hashlib
    import hmac as _hmac

    _set_secret(monkeypatch, _SECRET)
    # Build a payload with exp == iat (a zero/negative window) and sign it correctly.
    payload = {
        "tenant_id": "tenant-A",
        "admin_user_id": "op-1",
        "role": "tenant_admin",
        "auth_method": "sso",
        "iat": 2_000,
        "exp": 2_000,  # exp == iat -> invalid window
        "jti": "deadbeef",
    }
    payload_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    sig = (
        base64.urlsafe_b64encode(
            _hmac.new(_SECRET.encode(), payload_b64.encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    # now=1_999 -> not yet "expired" by the exp<=now check, so the exp<=iat guard is
    # the rejecting control under test.
    with pytest.raises(OperatorSessionError):
        verify(f"{payload_b64}.{sig}", now=1_999)

    # exp strictly before iat -> also rejected.
    payload["exp"] = 1_900
    payload_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    sig = (
        base64.urlsafe_b64encode(
            _hmac.new(_SECRET.encode(), payload_b64.encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(OperatorSessionError):
        verify(f"{payload_b64}.{sig}", now=1_950)


def test_tampered_signature_rejected(monkeypatch):
    """Flipping a signature byte -> rejected (constant-time compare)."""
    _set_secret(monkeypatch, _SECRET)
    token = mint(_principal())
    payload_b64, sig = token.split(".", 1)
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(OperatorSessionError):
        verify(f"{payload_b64}.{bad_sig}")


def test_tampered_payload_rejected(monkeypatch):
    """Re-pinning the payload to another tenant breaks the signature (vector 1)."""
    _set_secret(monkeypatch, _SECRET)
    token = mint(_principal(tenant_id="tenant-A"))
    payload_b64, sig = token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["tenant_id"] = "tenant-B"  # attacker re-pins to another tenant
    forged_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(OperatorSessionError):
        verify(f"{forged_b64}.{sig}")  # original sig no longer matches


def test_wrong_secret_rejected(monkeypatch):
    """A token minted under one secret is rejected when verified under another."""
    _set_secret(monkeypatch, _SECRET)
    token = mint(_principal())
    _set_secret(monkeypatch, _OTHER_SECRET)
    with pytest.raises(OperatorSessionError):
        verify(token)


def test_unset_secret_fails_closed(monkeypatch):
    """Unset SENTINEL_ADMIN_SESSION_SECRET -> mint AND verify raise (fail-closed)."""
    _set_secret(monkeypatch, None)
    with pytest.raises(OperatorSessionError):
        mint(_principal())
    with pytest.raises(OperatorSessionError):
        verify("anything.anything")


@pytest.mark.parametrize(
    "bad",
    ["", "no-dot", ".onlysig", "onlypayload.", "a.b.c", "...."],
)
def test_malformed_token_rejected(monkeypatch, bad):
    """Structurally malformed tokens are rejected (fail-closed)."""
    _set_secret(monkeypatch, _SECRET)
    with pytest.raises(OperatorSessionError):
        verify(bad)
