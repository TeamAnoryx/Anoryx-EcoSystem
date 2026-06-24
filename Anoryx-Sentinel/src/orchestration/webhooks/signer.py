"""HMAC-SHA256 signer for outbound webhook deliveries (F-020, ADR-0023 §5.5).

Signing contract (D4):
  - Generic / Splunk deliveries are signed: HMAC-SHA256(signing_secret, f"{ts}.{body}")
  - The timestamp is INSIDE the signed payload — `HMAC(secret, f"{ts}.{body}")` — so
    a replay cannot strip it by removing a header.
  - The request carries X-Sentinel-Timestamp (the ts used to build the signature).
  - Receivers verify by recomputing the HMAC with the recorded ts value and comparing
    to X-Sentinel-Signature header; reject if |now - ts| > tolerance.
  - Slack / Jira use native auth (Slack secret-in-URL / signing-secret, Jira API token)
    and are NOT double-wrapped by this signer.
  - Tolerance: WEBHOOK_SIGNATURE_TOLERANCE_SECONDS = 300 (Slack/Stripe convention).

NEVER log: signing_secret plaintext, computed signature values, request bodies.
The signing_secret is decrypted from the DB blob via secret_box.decrypt at
send time only; it is NEVER stored outside that ephemeral call stack.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from orchestration.webhooks.config import WEBHOOK_SIGNATURE_TOLERANCE_SECONDS

# Providers that are NOT HMAC-signed by this module (native auth only).
_NATIVE_AUTH_PROVIDERS: frozenset[str] = frozenset({"slack", "jira"})


@dataclass(frozen=True, slots=True)
class SignedHeaders:
    """Headers to add to the outbound webhook request.

    Fields
    ------
    x_sentinel_timestamp:
        Unix epoch (integer seconds, UTC) used as the ts component of the
        HMAC input.  Receivers MUST reject when |now - ts| > tolerance.
    x_sentinel_signature:
        Hex-encoded HMAC-SHA256(signing_secret, f"{ts}.{body}").
    """

    x_sentinel_timestamp: str
    x_sentinel_signature: str


def sign_body(signing_secret: bytes, body: str) -> SignedHeaders:
    """Compute HMAC-SHA256 signature headers for *body*.

    Parameters
    ----------
    signing_secret:
        Raw (decrypted) signing key bytes.  NEVER log this value.
    body:
        The serialized request body string (UTF-8 encoded for HMAC input).

    Returns
    -------
    SignedHeaders with the timestamp and hex signature.
    """
    ts = str(int(time.time()))
    # Signed payload: "{timestamp}.{body}" (Slack convention — timestamp-in-body).
    signed_payload = f"{ts}.{body}".encode("utf-8")
    digest = hmac.new(signing_secret, signed_payload, hashlib.sha256).hexdigest()
    return SignedHeaders(
        x_sentinel_timestamp=ts,
        x_sentinel_signature=f"sha256={digest}",
    )


def should_sign(provider: str) -> bool:
    """Return True when the provider requires Sentinel HMAC signing (not native auth)."""
    return provider.lower() not in _NATIVE_AUTH_PROVIDERS


def verify_within_tolerance(
    timestamp_str: str,
    *,
    tolerance_seconds: int = WEBHOOK_SIGNATURE_TOLERANCE_SECONDS,
    _now: float | None = None,
) -> bool:
    """Return True when *timestamp_str* is within the replay-rejection window.

    Used by RECEIVERS (and tests) to confirm a delivered timestamp is fresh.
    *_now* is a test-injection seam; production code omits it.
    """
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    now = _now if _now is not None else time.time()
    return abs(now - ts) <= tolerance_seconds
