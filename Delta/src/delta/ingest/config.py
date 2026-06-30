"""Ingest configuration — fail-loud secret resolution (no secret ever logged).

The Orchestrator->Delta consume seam is authenticated with a shared HMAC secret
(ADR-0004 §3.3). The secret is read from the environment at startup and the app
refuses to start without it (fail-loud), exactly like the Orchestrator's inbound
``ORCH_INGEST_HMAC_SECRET``. mTLS is deferred to a later infra task (O-008); until
then the HMAC secret-holder is the peer authenticator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Header + signing conventions for the Orchestrator->Delta channel (mirrors the
# inbound Sentinel->Orchestrator pattern, in the outbound direction).
SIGNATURE_HEADER = "X-Orchestrator-Signature"
TIMESTAMP_HEADER = "X-Orchestrator-Timestamp"
ATTEMPT_HEADER = "X-Orchestrator-Attempt"
SIGNATURE_PREFIX = "sha256="

# Replay window for the signed timestamp (seconds), identical to the inbound seam.
HMAC_TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class IngestSettings:
    """Resolved ingest settings. Constructed via :func:`load_settings` (fail-loud)."""

    hmac_secret: bytes


def load_settings() -> IngestSettings:
    """Resolve ingest settings from the environment. Raises if the secret is unset.

    The secret is returned as UTF-8 bytes and never logged or echoed.
    """
    raw = os.environ.get("DELTA_INGEST_HMAC_SECRET", "")
    if not raw:
        raise RuntimeError(
            "DELTA_INGEST_HMAC_SECRET is not set. This is the shared secret that "
            "authenticates the Orchestrator->Delta consume seam. Delta refuses to "
            "start without it (fail-closed). See Delta/.env.example."
        )
    return IngestSettings(hmac_secret=raw.encode("utf-8"))
