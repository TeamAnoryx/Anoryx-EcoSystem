"""Inbound HMAC verification for the ingest seam (O-003, ADR-0003).

The first INBOUND HMAC verifier in the ecosystem. Mirrors the F-020 outbound signer
contract (Anoryx-Sentinel/src/orchestration/webhooks/signer.py): the signer computes
`HMAC-SHA256(secret, "{timestamp}.{body}")` and sends `X-Sentinel-Signature: sha256=<hex>`
plus `X-Sentinel-Timestamp` (Unix seconds). This receiver recomputes over the RAW body
and compares in constant time, and rejects a timestamp outside the ±window (replay
defense).

Outcome → HTTP status mapping (ADR-0003):
  OK              → proceed (200-class).
  UNAUTHENTICATED → 401: a header is absent or malformed ("who are you?").
  REJECTED        → 403: headers well-formed but the timestamp is stale OR the signature
                    does not match ("present, but not permitted") — the contract's
                    Forbidden case ("timestamp outside the ±300s replay window, or a
                    signature mismatch").

NEVER log the secret, the computed digest, or the body.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
from dataclasses import dataclass


class HmacOutcome(enum.Enum):
    OK = "ok"
    UNAUTHENTICATED = "unauthenticated"  # -> 401
    REJECTED = "rejected"  # -> 403


@dataclass(frozen=True, slots=True)
class HmacResult:
    outcome: HmacOutcome
    #: A stable, PII-free machine code for the error body (never leaks crypto material).
    code: str


_SIG_PREFIX = "sha256="
_SIG_HEX_LEN = 64  # SHA-256 hex digest length
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")
_OK = HmacResult(HmacOutcome.OK, "ok")


def verify_ingest_signature(
    *,
    secret: bytes,
    raw_body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
    tolerance_seconds: int,
    now: float,
) -> HmacResult:
    """Verify the per-event HMAC body signature. *now* is injected (no implicit clock).

    Returns an HmacResult; the caller maps the outcome to 401/403.
    """
    # --- Header presence / shape (malformed -> 401) ---------------------------- #
    if not signature_header or not signature_header.startswith(_SIG_PREFIX):
        return HmacResult(HmacOutcome.UNAUTHENTICATED, "signature_missing")
    if not timestamp_header:
        return HmacResult(HmacOutcome.UNAUTHENTICATED, "timestamp_missing")
    try:
        ts = int(timestamp_header)
    except (ValueError, TypeError):
        return HmacResult(HmacOutcome.UNAUTHENTICATED, "timestamp_malformed")

    provided_hex = signature_header[len(_SIG_PREFIX) :]
    if not provided_hex:
        return HmacResult(HmacOutcome.UNAUTHENTICATED, "signature_missing")
    # A SHA-256 hex digest is exactly 64 hex chars. Reject anything else as malformed
    # BEFORE hmac.compare_digest — a non-ASCII header value would otherwise raise TypeError
    # ("comparing strings with non-ASCII characters") and surface as a 503 instead of a
    # clean 401 (audit L-1). This is a charset/shape gate, not a verification.
    if len(provided_hex) != _SIG_HEX_LEN or any(c not in _HEXDIGITS for c in provided_hex):
        return HmacResult(HmacOutcome.UNAUTHENTICATED, "signature_malformed")

    # --- Replay window (stale -> 403) ----------------------------------------- #
    if abs(now - ts) > tolerance_seconds:
        return HmacResult(HmacOutcome.REJECTED, "timestamp_out_of_window")

    # --- Constant-time signature compare (mismatch -> 403) -------------------- #
    signed_payload = f"{ts}.".encode("utf-8") + raw_body
    expected_hex = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hex, provided_hex):
        return HmacResult(HmacOutcome.REJECTED, "signature_invalid")

    return _OK
