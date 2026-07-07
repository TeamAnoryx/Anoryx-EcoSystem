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

    service_token is the LEGACY coarse peer bearer (ORCH_SERVICE_TOKEN). Post-O-006 it NO
    LONGER gates the query/distribution seams — those enforce per-tenant read authz via the
    `query_service_tokens` principal (see security.py). It is still parsed (may be None) purely
    to avoid env breakage and is unused by those seams. sentinel_admin_token may be None (absence
    is not fatal); the request boundary enforces its presence fail-closed. targets maps
    sentinel_id -> base URL (a static minimal list; the dynamic registry resolver is O-005).
    Tokens are never logged.
    """

    #: LEGACY — no longer used to gate the query/distribution seams post-O-006 (per-tenant
    #: query_service_tokens do). Retained only for env-parse compatibility.
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


def _env_bool(name: str) -> bool:
    """Read a boolean flag from the environment (1/true/on/yes → True; else False)."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "on", "yes")


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
      ORCH_SERVICE_TOKEN            LEGACY coarse peer bearer — post-O-006 it NO LONGER gates the
                                   query/distribution seams (per-tenant query_service_tokens do,
                                   via security.py). Still parsed for env compatibility; unused by
                                   those seams (None if unset).
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


# =========================================================================== #
# Multi-Sentinel coordination configuration (O-005, ADR-0005) — ADDITIVE, parallel to the
# distribution settings above. Resolved NON-FATALLY at app construction (mere absence is not
# fatal — an ingest/distribution-only deployment must not be forced to configure the registry).
# The inbound operator token (ORCH_ADMIN_TOKEN) is a NEW dedicated token distinct from the
# peer ORCH_SERVICE_TOKEN: the registry is operator-fleet infra, not a peer-ingest seam. It
# defaults to None and the request boundary enforces it fail-closed. SSRF endpoint validation
# is mandatory: the allowlist defaults EMPTY so only public https endpoints pass — a loopback
# / private endpoint must be explicitly allowlisted (the e2e opts 127.0.0.1 in). Tokens are
# never logged.
# =========================================================================== #

#: Default Sentinel health-probe path (a conventional readiness path; the shipped Sentinel-side
#: HTTP route does not yet exist — ADR-0005 honesty boundary E1, separate Sentinel task).
DEFAULT_SENTINEL_HEALTH_PATH: str = "/healthz"

#: Default per-attempt outbound HTTP timeout (seconds) for a health probe.
DEFAULT_HEALTH_HTTP_TIMEOUT_SECONDS: float = 10.0

#: Default staleness window (seconds): a healthy target last checked longer ago than this is
#: demoted, so a never-re-checked target is not trusted as healthy indefinitely.
DEFAULT_HEALTH_STALENESS_SECONDS: int = 300

#: Default consecutive-failure count at which a target transitions to `unreachable`
#: (below it → `degraded`).
DEFAULT_HEALTH_UNREACHABLE_THRESHOLD: int = 3


@dataclass(frozen=True, slots=True)
class CoordinationSettings:
    """Resolved multi-Sentinel coordination configuration (O-005, ADR-0005).

    admin_token may be None (absence is not fatal); the registry request boundary enforces
    presence fail-closed. endpoint_allowlist is the SSRF host/host:port allowlist (empty ⇒ only
    public https passes). distribution is the embedded O-004 distribution settings the
    coordinated push consumes unchanged (its `.targets` is overridden per-push from the
    registry). admin_token is never logged.
    """

    admin_token: str | None
    endpoint_allowlist: frozenset[str]
    allow_http: bool
    health_path: str
    health_timeout_seconds: float
    staleness_seconds: int
    unreachable_threshold: int
    distribution: DistributionSettings


def _endpoint_allowlist() -> frozenset[str]:
    """Parse ORCH_REGISTRY_ENDPOINT_ALLOWLIST (comma-separated host / host:port entries).

    Empty/unset → empty frozenset (fail-closed: only public https endpoints then pass). Entries
    are stripped, lowercased (hosts are case-insensitive), and empties dropped.
    """
    raw = os.environ.get("ORCH_REGISTRY_ENDPOINT_ALLOWLIST", "")
    return frozenset(entry.strip().lower() for entry in raw.split(",") if entry.strip())


def get_coordination_settings() -> CoordinationSettings:
    """Resolve coordination settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_ADMIN_TOKEN                   inbound operator bearer for registry CRUD + coordinate
                                         (None if unset → fail-closed at the boundary).
      ORCH_REGISTRY_ENDPOINT_ALLOWLIST   comma-separated host / host:port allowlist ("" if unset).
      ORCH_REGISTRY_ALLOW_HTTP           allow http scheme for allowlisted hosts (default false).
      ORCH_SENTINEL_HEALTH_PATH          health-probe path (default "/healthz").
      ORCH_HEALTH_HTTP_TIMEOUT           per-probe HTTP timeout seconds (default 10.0).
      ORCH_HEALTH_STALENESS_SECONDS      staleness window seconds (default 300, >= 0).
      ORCH_HEALTH_UNREACHABLE_THRESHOLD  consecutive failures → unreachable (default 3, >= 1).

    Tokens are never logged.
    """
    health_path = os.environ.get("ORCH_SENTINEL_HEALTH_PATH", "").strip() or (
        DEFAULT_SENTINEL_HEALTH_PATH
    )
    if not health_path.startswith("/"):
        health_path = "/" + health_path
    return CoordinationSettings(
        admin_token=_optional_token("ORCH_ADMIN_TOKEN"),
        endpoint_allowlist=_endpoint_allowlist(),
        allow_http=_env_bool("ORCH_REGISTRY_ALLOW_HTTP"),
        health_path=health_path,
        health_timeout_seconds=_env_float(
            "ORCH_HEALTH_HTTP_TIMEOUT", DEFAULT_HEALTH_HTTP_TIMEOUT_SECONDS, minimum=0.0
        ),
        staleness_seconds=_env_int(
            "ORCH_HEALTH_STALENESS_SECONDS", DEFAULT_HEALTH_STALENESS_SECONDS, minimum=0
        ),
        unreachable_threshold=_env_int(
            "ORCH_HEALTH_UNREACHABLE_THRESHOLD", DEFAULT_HEALTH_UNREACHABLE_THRESHOLD, minimum=1
        ),
        distribution=get_distribution_settings(),
    )
