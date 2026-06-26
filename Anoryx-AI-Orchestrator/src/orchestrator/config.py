"""Runtime configuration for the Orchestrator ingest pipeline (O-003, ADR-0003).

Values come from the environment only (never hardcoded secrets, never logged). The HMAC
signing secret is fail-loud: ingest cannot start without it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# The envelope schema_version values this bus accepts (v1 = [1]). Backs the
# reject-to-DLQ rule (ADR-0002 Fork C): an inbound envelope whose schema_version is not
# in this allow-list is routed to the DLQ (unknown_schema_version), never best-effort
# parsed. This is the internal allow-list; the GET /v1/bus/schema-versions read seam
# that publishes it is O-006.
SUPPORTED_SCHEMA_VERSIONS: frozenset[int] = frozenset({1})

#: The TRUSTED source_product for the ingest seam. mTLS provisioning is deferred to
#: O-008; until then the HMAC secret-holder is the interim peer authenticator and the
#: only authenticated ingest peer is Sentinel. source_product is stamped from THIS,
#: verified against the body, and never trusted from the body (rule 7, ADR-0002 threat 2).
INGEST_PEER_SOURCE_PRODUCT: str = "sentinel"

#: HMAC replay window (Slack/Stripe convention; matches the F-020 signer tolerance).
HMAC_TOLERANCE_SECONDS: int = 300


class ConfigError(RuntimeError):
    """Raised when a required configuration value is absent."""


@dataclass(frozen=True, slots=True)
class IngestSettings:
    """Resolved ingest configuration."""

    hmac_secret: bytes
    hmac_tolerance_seconds: int
    supported_schema_versions: frozenset[int]
    ingest_peer_source_product: str


def get_ingest_settings() -> IngestSettings:
    """Resolve ingest settings from the environment (fail-loud on a missing secret).

    ORCH_INGEST_HMAC_SECRET is the shared per-event HMAC signing secret. It is read as
    UTF-8 bytes and NEVER logged.
    """
    secret = os.environ.get("ORCH_INGEST_HMAC_SECRET", "")
    if not secret:
        raise ConfigError(
            "ORCH_INGEST_HMAC_SECRET is not set. The ingest seam cannot verify the "
            "per-event HMAC body signature without it."
        )
    return IngestSettings(
        hmac_secret=secret.encode("utf-8"),
        hmac_tolerance_seconds=HMAC_TOLERANCE_SECONDS,
        supported_schema_versions=SUPPORTED_SCHEMA_VERSIONS,
        ingest_peer_source_product=INGEST_PEER_SOURCE_PRODUCT,
    )
