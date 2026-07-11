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
    """Resolved ingest settings. Constructed via :func:`load_settings` (fail-loud).

    Two INDEPENDENT inbound secrets, one per seam — never shared, never reused:

    * ``hmac_secret``          — Orchestrator->Delta usage consume seam (POST /v1/ingest/usage).
    * ``revenue_hmac_secret``  — the X-005 monetization consume seam (POST /v1/ingest/revenue).
      DEDICATED per-source: because v1 accepts only ``source_product=rendly``, holding THIS
      secret === being Rendly, so ``source_product`` is server-resolved in code from the
      authenticated caller (never read from the body). A dedicated secret keeps the two
      seams' trust boundaries separate — a leak of one never authenticates the other.
    """

    hmac_secret: bytes
    revenue_hmac_secret: bytes


def load_settings() -> IngestSettings:
    """Resolve ingest settings from the environment. Raises if EITHER secret is unset.

    Each secret is returned as UTF-8 bytes and never logged or echoed. Both are required
    (fail-closed): the ingest app exposes both the usage and the revenue consume seams, so
    a missing secret for either is a deployment error, not a silent degrade.
    """
    raw = os.environ.get("DELTA_INGEST_HMAC_SECRET", "")
    if not raw:
        raise RuntimeError(
            "DELTA_INGEST_HMAC_SECRET is not set. This is the shared secret that "
            "authenticates the Orchestrator->Delta usage consume seam. Delta refuses to "
            "start without it (fail-closed). See Delta/deploy/secrets/README.md."
        )
    raw_revenue = os.environ.get("DELTA_REVENUE_INGEST_HMAC_SECRET", "")
    if not raw_revenue:
        raise RuntimeError(
            "DELTA_REVENUE_INGEST_HMAC_SECRET is not set. This is the DEDICATED per-source "
            "secret that authenticates the X-005 revenue consume seam (POST /v1/ingest/revenue); "
            "holding it identifies the caller as the source product (v1: rendly). It MUST be "
            "distinct from DELTA_INGEST_HMAC_SECRET. Delta refuses to start without it "
            "(fail-closed). See Delta/deploy/secrets/README.md."
        )
    return IngestSettings(
        hmac_secret=raw.encode("utf-8"),
        revenue_hmac_secret=raw_revenue.encode("utf-8"),
    )
