"""Runtime configuration for the Orchestrator ingest pipeline (O-003, ADR-0003).

Values come from the environment only (never hardcoded secrets, never logged). The HMAC
signing secret is fail-loud: ingest cannot start without it.
"""

from __future__ import annotations

import json
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


# =========================================================================== #
# Policy-distribution configuration (O-004, ADR-0004) — ADDITIVE, parallel to the
# ingest settings above. Resolved NON-FATALLY at app construction (unlike the fail-loud
# ingest HMAC secret): an ingest-only deployment must not be forced to configure the
# distribution seam. Misconfiguration is LOUD (a malformed targets map / non-numeric
# bound raises ConfigError); mere ABSENCE is not (tokens default to None, an empty
# targets map is {}). Tokens are NEVER logged.
# =========================================================================== #

#: Default Sentinel admin-intake path (the documented admin-intake contract; the shipped
#: Sentinel-side HTTP route does not yet exist — ADR-0004 Fork F honesty boundary).
DEFAULT_SENTINEL_INTAKE_PATH: str = "/admin/policies/intake"

#: Default bounded-retry attempt ceiling (Fork D — bounded, never unbounded).
DEFAULT_DISTRIBUTION_MAX_ATTEMPTS: int = 3

#: Default base backoff (seconds) for the exponential retry schedule.
DEFAULT_DISTRIBUTION_BACKOFF_SECONDS: float = 0.5

#: Default per-attempt outbound HTTP timeout (seconds) for the Sentinel intake call.
DEFAULT_DISTRIBUTION_HTTP_TIMEOUT_SECONDS: float = 10.0


@dataclass(frozen=True, slots=True)
class DistributionSettings:
    """Resolved policy-distribution configuration (O-004, ADR-0004).

    service_token / sentinel_admin_token may be None (absence is not fatal); the request
    boundary enforces presence fail-closed. targets maps sentinel_id -> base URL (a static
    minimal list; the dynamic registry resolver is O-005). Tokens are never logged.
    """

    service_token: str | None
    sentinel_admin_token: str | None
    targets: dict[str, str]
    intake_path: str
    max_attempts: int
    backoff_seconds: float
    http_timeout_seconds: float


def _optional_token(name: str) -> str | None:
    """Read an optional bearer token from the environment (None when unset/empty).

    Mirrors the ingest `if not secret` convention. NEVER logs the value.
    """
    raw = os.environ.get(name, "")
    return raw if raw else None


def _env_int(name: str, default: int, *, minimum: int) -> int:
    """Read a bounded int from the environment (absence → default; bad value → ConfigError)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer.") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}.")
    return value


def _env_float(name: str, default: float, *, minimum: float) -> float:
    """Read a bounded float from the environment (absence → default; bad value → ConfigError)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number.") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}.")
    return value


def _distribution_targets() -> dict[str, str]:
    """Parse ORCH_DISTRIBUTION_TARGETS (a JSON object: sentinel_id -> base URL).

    Unset/empty → {} (absence is not fatal). A non-JSON value, a non-object, or a non-string
    key/value → ConfigError (misconfiguration is loud).
    """
    raw = os.environ.get("ORCH_DISTRIBUTION_TARGETS", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(
            "ORCH_DISTRIBUTION_TARGETS is not valid JSON. It must be a JSON object "
            "mapping sentinel_id -> base URL."
        ) from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
    ):
        raise ConfigError(
            "ORCH_DISTRIBUTION_TARGETS must be a JSON object mapping a string sentinel_id "
            "to a string base URL."
        )
    return parsed


def get_distribution_settings() -> DistributionSettings:
    """Resolve distribution settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_SERVICE_TOKEN            inbound bearer the POST/GET seams require (None if unset).
      SENTINEL_ADMIN_TOKEN         outbound bearer presented to Sentinel intake (None if unset).
      ORCH_DISTRIBUTION_TARGETS    JSON object {sentinel_id: base_url} ({} if unset).
      ORCH_SENTINEL_INTAKE_PATH    Sentinel intake path (default "/admin/policies/intake").
      ORCH_DISTRIBUTION_MAX_ATTEMPTS  bounded-retry ceiling (default 3, >= 1).
      ORCH_DISTRIBUTION_BACKOFF_SECONDS  base backoff seconds (default 0.5).
      ORCH_DISTRIBUTION_HTTP_TIMEOUT  per-attempt HTTP timeout seconds (default 10.0).

    Tokens are never logged.
    """
    return DistributionSettings(
        service_token=_optional_token("ORCH_SERVICE_TOKEN"),
        sentinel_admin_token=_optional_token("SENTINEL_ADMIN_TOKEN"),
        targets=_distribution_targets(),
        intake_path=os.environ.get("ORCH_SENTINEL_INTAKE_PATH", "").strip()
        or DEFAULT_SENTINEL_INTAKE_PATH,
        max_attempts=_env_int(
            "ORCH_DISTRIBUTION_MAX_ATTEMPTS", DEFAULT_DISTRIBUTION_MAX_ATTEMPTS, minimum=1
        ),
        backoff_seconds=_env_float(
            "ORCH_DISTRIBUTION_BACKOFF_SECONDS", DEFAULT_DISTRIBUTION_BACKOFF_SECONDS, minimum=0.0
        ),
        http_timeout_seconds=_env_float(
            "ORCH_DISTRIBUTION_HTTP_TIMEOUT", DEFAULT_DISTRIBUTION_HTTP_TIMEOUT_SECONDS, minimum=0.0
        ),
    )
