"""HMAC-SHA256 signer for the Orchestrator->Delta consume seam (ADR-0004 §3.3).

Mirrors the inbound Sentinel->Orchestrator HMAC pattern in the outbound direction.
The signature is over "{timestamp}.{raw_body}" with a shared secret; Delta verifies
the same bytes. The secret is read fail-loud from the environment and never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

SIGNATURE_HEADER = "X-Orchestrator-Signature"
TIMESTAMP_HEADER = "X-Orchestrator-Timestamp"
ATTEMPT_HEADER = "X-Orchestrator-Attempt"
_SECRET_ENV = "DELTA_INGEST_HMAC_SECRET"  # noqa: S105 - env var NAME, not a secret value


def _secret() -> bytes:
    raw = os.environ.get(_SECRET_ENV, "")
    if not raw:
        raise RuntimeError(
            f"{_SECRET_ENV} is not set. This is the shared secret authenticating the "
            "Orchestrator->Delta consume seam. The dispatcher refuses to sign without it."
        )
    return raw.encode("utf-8")


def sign(body: bytes, *, attempt: int, timestamp: int | None = None) -> dict[str, str]:
    """Return the signed request headers for POSTing ``body`` to the Delta inbound seam.

    The caller MUST transmit exactly ``body`` (the same bytes signed here); Delta
    re-computes the HMAC over the received raw body, so any re-serialization between
    signing and sending would break verification.
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    ts_str = str(ts)
    signed = ts_str.encode("ascii") + b"." + body
    digest = hmac.new(_secret(), signed, hashlib.sha256).hexdigest()
    return {
        TIMESTAMP_HEADER: ts_str,
        SIGNATURE_HEADER: f"sha256={digest}",
        ATTEMPT_HEADER: str(int(attempt)),
        "Content-Type": "application/json",
    }
