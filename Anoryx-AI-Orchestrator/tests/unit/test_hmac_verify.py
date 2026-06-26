"""Unit tests for the inbound HMAC verifier (O-003)."""

from __future__ import annotations

import hashlib
import hmac

from orchestrator.hmac_verify import HmacOutcome, verify_ingest_signature

_SECRET = b"unit-test-secret"
_BODY = b'{"hello":"world"}'
_NOW = 1_781_784_000.0


def _sign(ts: int, body: bytes, secret: bytes = _SECRET) -> str:
    signed = f"{ts}.".encode("utf-8") + body
    return "sha256=" + hmac.new(secret, signed, hashlib.sha256).hexdigest()


def test_valid_signature_ok():
    ts = int(_NOW)
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header=_sign(ts, _BODY),
        timestamp_header=str(ts),
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.OK


def test_missing_signature_is_unauthenticated():
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header=None,
        timestamp_header=str(int(_NOW)),
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.UNAUTHENTICATED


def test_malformed_signature_prefix_is_unauthenticated():
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header="deadbeef",  # no sha256= prefix
        timestamp_header=str(int(_NOW)),
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.UNAUTHENTICATED


def test_missing_timestamp_is_unauthenticated():
    ts = int(_NOW)
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header=_sign(ts, _BODY),
        timestamp_header=None,
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.UNAUTHENTICATED


def test_non_numeric_timestamp_is_unauthenticated():
    ts = int(_NOW)
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header=_sign(ts, _BODY),
        timestamp_header="not-a-number",
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.UNAUTHENTICATED


def test_stale_timestamp_is_rejected():
    ts = int(_NOW) - 600  # 10 minutes old, window is 300s
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header=_sign(ts, _BODY),
        timestamp_header=str(ts),
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.REJECTED
    assert result.code == "timestamp_out_of_window"


def test_wrong_signature_is_rejected():
    ts = int(_NOW)
    bad = _sign(ts, _BODY, secret=b"wrong-secret")
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY,
        signature_header=bad,
        timestamp_header=str(ts),
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.REJECTED
    assert result.code == "signature_invalid"


def test_tampered_body_is_rejected():
    ts = int(_NOW)
    sig = _sign(ts, _BODY)
    result = verify_ingest_signature(
        secret=_SECRET,
        raw_body=_BODY + b"x",  # body changed after signing
        signature_header=sig,
        timestamp_header=str(ts),
        tolerance_seconds=300,
        now=_NOW,
    )
    assert result.outcome is HmacOutcome.REJECTED
