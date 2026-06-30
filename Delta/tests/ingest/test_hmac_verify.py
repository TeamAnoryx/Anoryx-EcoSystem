"""Vector 6 — HMAC verification of the Orchestrator->Delta consume seam (UNIT, no DB).

Exercises ``delta.ingest.hmac_verify.verify_signature`` directly: a valid signature
passes; every malformed / forged / replayed input is fail-closed to False. The clock is
injected via ``now`` so the window checks are deterministic.
"""

from __future__ import annotations

import hashlib
import hmac

from delta.ingest.hmac_verify import verify_signature

_SECRET = b"unit-test-secret"  # noqa: S105 - test-only fake
_BODY = b'{"event_type":"usage","tenant_id":"t"}'


def _digest(secret: bytes, ts: int, body: bytes) -> str:
    """Recompute the expected hex digest over f"{ts}.".bytes + body (signer contract)."""
    signed = f"{ts}".encode("ascii") + b"." + body
    return hmac.new(secret, signed, hashlib.sha256).hexdigest()


def _headers(secret: bytes, ts: int, body: bytes) -> dict[str, str]:
    return {"ts": str(ts), "sig": "sha256=" + _digest(secret, ts, body)}


def test_valid_signature_passes():
    ts = 1_000_000
    h = _headers(_SECRET, ts, _BODY)
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=h["ts"],
            signature_header=h["sig"],
            raw_body=_BODY,
            now=float(ts),
        )
        is True
    )


def test_missing_timestamp_header_fails():
    h = _headers(_SECRET, 1_000_000, _BODY)
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=None,
            signature_header=h["sig"],
            raw_body=_BODY,
            now=1_000_000.0,
        )
        is False
    )


def test_missing_signature_header_fails():
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header="1000000",
            signature_header=None,
            raw_body=_BODY,
            now=1_000_000.0,
        )
        is False
    )


def test_wrong_secret_fails():
    ts = 1_000_000
    forged = _headers(b"the-wrong-secret", ts, _BODY)  # signed with a different secret
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=forged["ts"],
            signature_header=forged["sig"],
            raw_body=_BODY,
            now=float(ts),
        )
        is False
    )


def test_tampered_body_fails():
    ts = 1_000_000
    h = _headers(_SECRET, ts, _BODY)  # signature over _BODY
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=h["ts"],
            signature_header=h["sig"],
            raw_body=_BODY + b" tampered",  # verify a DIFFERENT body
            now=float(ts),
        )
        is False
    )


def test_expired_timestamp_fails():
    # Signature is valid for ts, but ts is 400s in the past (window is +/-300s).
    ts = 1_000_000
    now = ts + 400
    h = _headers(_SECRET, ts, _BODY)
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=h["ts"],
            signature_header=h["sig"],
            raw_body=_BODY,
            now=float(now),
        )
        is False
    )


def test_future_timestamp_beyond_window_fails():
    ts = 1_000_000
    now = ts - 400  # ts is 400s in the future relative to now
    h = _headers(_SECRET, ts, _BODY)
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=h["ts"],
            signature_header=h["sig"],
            raw_body=_BODY,
            now=float(now),
        )
        is False
    )


def test_non_integer_timestamp_fails():
    h = _headers(_SECRET, 1_000_000, _BODY)
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header="not-a-number",
            signature_header=h["sig"],
            raw_body=_BODY,
            now=1_000_000.0,
        )
        is False
    )


def test_signature_without_sha256_prefix_fails():
    ts = 1_000_000
    bare_hex = _digest(_SECRET, ts, _BODY)  # correct digest, but no "sha256=" prefix
    assert (
        verify_signature(
            secret=_SECRET,
            timestamp_header=str(ts),
            signature_header=bare_hex,
            raw_body=_BODY,
            now=float(ts),
        )
        is False
    )
