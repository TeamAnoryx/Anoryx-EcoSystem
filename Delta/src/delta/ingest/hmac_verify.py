"""HMAC-SHA256 verification for the Orchestrator->Delta consume seam (vector 6).

Mirrors the Orchestrator's inbound ``hmac_verify`` (Sentinel F-020 signer lineage),
in the verify direction. The signature is computed over ``"{timestamp}.{raw_body}"``
with the shared secret; a constant-time compare and a ±window replay check guard
against forgery and replay. A request that fails ANY check is rejected — it never
reaches the ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from .config import HMAC_TOLERANCE_SECONDS, SIGNATURE_PREFIX


def _expected_signature(secret: bytes, timestamp: str, raw_body: bytes) -> str:
    signed = timestamp.encode("ascii", "strict") + b"." + raw_body
    return hmac.new(secret, signed, hashlib.sha256).hexdigest()


def verify_signature(
    *,
    secret: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    raw_body: bytes,
    now: float | None = None,
) -> bool:
    """Return True iff the signature is valid and the timestamp is within tolerance.

    Fail-closed on every malformed input: missing headers, a non-integer timestamp, a
    timestamp outside the ±tolerance window, a signature lacking the ``sha256=``
    prefix, or a digest mismatch all return False. The hex compare is constant-time.
    """
    if not timestamp_header or not signature_header:
        return False
    if not signature_header.startswith(SIGNATURE_PREFIX):
        return False

    # Fail-closed on a non-ASCII timestamp: int() accepts unicode decimal digits
    # (e.g. Arabic-Indic), but the signing string is ascii-encoded, so a unicode-digit
    # timestamp would raise UnicodeEncodeError downstream and surface as a retryable 503
    # instead of a terminal 401. Reject it here so every malformed input returns False.
    if not timestamp_header.isascii():
        return False

    try:
        ts = int(timestamp_header)
    except (TypeError, ValueError):
        return False

    current = time.time() if now is None else now
    if abs(current - ts) > HMAC_TOLERANCE_SECONDS:
        return False

    provided = signature_header[len(SIGNATURE_PREFIX) :]
    expected = _expected_signature(secret, timestamp_header, raw_body)
    # constant-time compare; hmac.compare_digest handles unequal lengths safely.
    return hmac.compare_digest(provided, expected)
