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


# =========================================================================== #
# Governed relay configuration (O-009, ADR-0009) — ADDITIVE, embedded in
# CoordinationSettings below (the relay reuses the registry's SSRF gate + health
# staleness rule the same way CoordinationSettings already embeds DistributionSettings).
# Resolved NON-FATALLY: absence is not fatal — a deployment that never enables the relay
# must not be forced to configure it. source_tokens defaults to {} ⇒ the relay seam
# fail-closed-401s every request (no configured source can ever match). Tokens are never
# logged.
# =========================================================================== #

#: The only source_products the relay recognises (Delta / Rendly per the ecosystem data-flow
#: diagram, CLAUDE.md). A configured ORCH_RELAY_SOURCE_TOKENS key outside this set is a loud
#: misconfiguration, not a silent no-op.
KNOWN_RELAY_SOURCE_PRODUCTS: frozenset[str] = frozenset({"delta", "rendly"})

#: Default relay-eligible Sentinel paths — Sentinel's shipped OpenAI-compatible surface
#: (F-001). Deliberately a closed allowlist, not an open passthrough: the relay is a governed
#: seam onto Sentinel's real gateway, not a general-purpose reverse proxy to any Sentinel path.
DEFAULT_RELAY_ALLOWED_PATHS: frozenset[str] = frozenset(
    {"/v1/chat/completions", "/v1/completions", "/v1/models"}
)

#: Default per-request outbound HTTP timeout (seconds) for a relay dispatch.
DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS: float = 30.0

#: Default request-body size cap (bytes). Chat-completions payloads run larger than the
#: registry's 64 KiB operator-body cap, so the relay gets its own, more generous ceiling.
DEFAULT_RELAY_MAX_BODY_BYTES: int = 1_048_576


@dataclass(frozen=True, slots=True)
class RelaySettings:
    """Resolved governed-relay configuration (O-009, ADR-0009).

    source_tokens maps source_product ("delta" | "rendly") -> its shared bearer token; the
    relay router resolves source_product FROM the presented token (server-resolved, never
    client-claimed), mirroring the ingest seam's source_product discipline. allowed_paths is
    the closed set of Sentinel paths the relay may dispatch to. Tokens are never logged.
    """

    source_tokens: dict[str, str]
    allowed_paths: frozenset[str]
    http_timeout_seconds: float
    max_body_bytes: int


def _relay_source_tokens() -> dict[str, str]:
    """Parse ORCH_RELAY_SOURCE_TOKENS (a JSON object: source_product -> bearer token).

    Unset/empty → {} (absence is not fatal; the seam is then fail-closed-401 for everyone).
    A non-JSON value, a non-object, a non-string key/value, an empty token, or a key outside
    KNOWN_RELAY_SOURCE_PRODUCTS → ConfigError (misconfiguration is loud).
    """
    raw = os.environ.get("ORCH_RELAY_SOURCE_TOKENS", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(
            "ORCH_RELAY_SOURCE_TOKENS is not valid JSON. It must be a JSON object mapping "
            "source_product -> bearer token."
        ) from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and v for k, v in parsed.items()
    ):
        raise ConfigError(
            "ORCH_RELAY_SOURCE_TOKENS must be a JSON object mapping a string source_product "
            "to a non-empty string bearer token."
        )
    if not set(parsed) <= KNOWN_RELAY_SOURCE_PRODUCTS:
        raise ConfigError(
            "ORCH_RELAY_SOURCE_TOKENS keys must be drawn from "
            f"{sorted(KNOWN_RELAY_SOURCE_PRODUCTS)}."
        )
    return parsed


def _relay_allowed_paths() -> frozenset[str]:
    """Parse ORCH_RELAY_ALLOWED_PATHS (comma-separated paths). Unset/empty → the default set."""
    raw = os.environ.get("ORCH_RELAY_ALLOWED_PATHS", "").strip()
    if not raw:
        return DEFAULT_RELAY_ALLOWED_PATHS
    paths = frozenset(p.strip() for p in raw.split(",") if p.strip())
    if not paths:
        return DEFAULT_RELAY_ALLOWED_PATHS
    for p in paths:
        if not p.startswith("/"):
            raise ConfigError("ORCH_RELAY_ALLOWED_PATHS entries must start with '/'.")
    return paths


def get_relay_settings() -> RelaySettings:
    """Resolve relay settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_RELAY_SOURCE_TOKENS    JSON object {"delta"|"rendly": bearer_token} ({} if unset).
      ORCH_RELAY_ALLOWED_PATHS    comma-separated Sentinel path allowlist (default the three
                                  shipped OpenAI-compatible paths).
      ORCH_RELAY_HTTP_TIMEOUT     per-dispatch outbound HTTP timeout seconds (default 30.0).
      ORCH_RELAY_MAX_BODY_BYTES   request-body size cap in bytes (default 1 MiB, >= 1).

    Tokens are never logged.
    """
    return RelaySettings(
        source_tokens=_relay_source_tokens(),
        allowed_paths=_relay_allowed_paths(),
        http_timeout_seconds=_env_float(
            "ORCH_RELAY_HTTP_TIMEOUT", DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS, minimum=0.0
        ),
        max_body_bytes=_env_int(
            "ORCH_RELAY_MAX_BODY_BYTES", DEFAULT_RELAY_MAX_BODY_BYTES, minimum=1
        ),
    )


@dataclass(frozen=True, slots=True)
class CoordinationSettings:
    """Resolved multi-Sentinel coordination configuration (O-005, ADR-0005).

    admin_token may be None (absence is not fatal); the registry request boundary enforces
    presence fail-closed. endpoint_allowlist is the SSRF host/host:port allowlist (empty ⇒ only
    public https passes). distribution is the embedded O-004 distribution settings the
    coordinated push consumes unchanged (its `.targets` is overridden per-push from the
    registry). relay is the embedded O-009 governed-relay settings (ADR-0009); the relay reuses
    THIS struct's endpoint_allowlist / allow_http / staleness_seconds for its own registry-driven
    SSRF + health gating, the same way the coordinated push reuses distribution. admin_token is
    never logged.
    """

    admin_token: str | None
    endpoint_allowlist: frozenset[str]
    allow_http: bool
    health_path: str
    health_timeout_seconds: float
    staleness_seconds: int
    unreachable_threshold: int
    distribution: DistributionSettings
    relay: RelaySettings


def _endpoint_allowlist() -> frozenset[str]:
    """Parse ORCH_REGISTRY_ENDPOINT_ALLOWLIST (comma-separated host / host:port entries).

    Empty/unset → empty frozenset (fail-closed: only public https endpoints then pass). Entries
    are stripped, lowercased (hosts are case-insensitive), and empties dropped.
    """
    raw = os.environ.get("ORCH_REGISTRY_ENDPOINT_ALLOWLIST", "")
    return frozenset(entry.strip().lower() for entry in raw.split(",") if entry.strip())


# =========================================================================== #
# Cross-product identity-event correlation configuration (O-010, ADR-0010) — ADDITIVE,
# STANDALONE (not nested in CoordinationSettings — unlike the relay, this seam has no
# registry/SSRF/health dependency). Resolved NON-FATALLY: absence is not fatal — an
# unconfigured seam fail-closed-401s every ingest request (no configured source can ever
# match).
# =========================================================================== #

#: The source_products the identity-event seam recognises. EVERY ecosystem product may
#: report identity events here (unlike the O-009 relay, where Sentinel is only ever the
#: relay TARGET, never a caller) — Sentinel's own SSO logins, Delta's admin-token uses, and
#: Rendly's JWT verifications are all legitimate "who accessed what, where" sources.
KNOWN_IDENTITY_SOURCE_PRODUCTS: frozenset[str] = frozenset({"sentinel", "delta", "rendly"})

#: Default request-body size cap (bytes) for one identity-event ingest.
DEFAULT_IDENTITY_MAX_BODY_BYTES: int = 8192


@dataclass(frozen=True, slots=True)
class IdentitySettings:
    """Resolved identity-event correlation configuration (O-010, ADR-0010).

    source_tokens maps source_product ("sentinel" | "delta" | "rendly") -> its shared bearer
    token; the router resolves source_product FROM the presented token (server-resolved,
    never client-claimed), mirroring the ingest/relay seams' source_product discipline.
    Tokens are never logged.
    """

    source_tokens: dict[str, str]
    max_body_bytes: int


def _identity_source_tokens() -> dict[str, str]:
    """Parse ORCH_IDENTITY_SOURCE_TOKENS (a JSON object: source_product -> bearer token).

    Unset/empty → {} (absence is not fatal; the seam is then fail-closed-401 for everyone).
    A non-JSON value, a non-object, a non-string key/value, an empty token, or a key outside
    KNOWN_IDENTITY_SOURCE_PRODUCTS → ConfigError (misconfiguration is loud).
    """
    raw = os.environ.get("ORCH_IDENTITY_SOURCE_TOKENS", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(
            "ORCH_IDENTITY_SOURCE_TOKENS is not valid JSON. It must be a JSON object mapping "
            "source_product -> bearer token."
        ) from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and v for k, v in parsed.items()
    ):
        raise ConfigError(
            "ORCH_IDENTITY_SOURCE_TOKENS must be a JSON object mapping a string source_product "
            "to a non-empty string bearer token."
        )
    if not set(parsed) <= KNOWN_IDENTITY_SOURCE_PRODUCTS:
        raise ConfigError(
            "ORCH_IDENTITY_SOURCE_TOKENS keys must be drawn from "
            f"{sorted(KNOWN_IDENTITY_SOURCE_PRODUCTS)}."
        )
    return parsed


def get_identity_settings() -> IdentitySettings:
    """Resolve identity-event settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_IDENTITY_SOURCE_TOKENS   JSON object {"sentinel"|"delta"|"rendly": bearer_token}
                                   ({} if unset).
      ORCH_IDENTITY_MAX_BODY_BYTES  request-body size cap in bytes (default 8192, >= 1).

    Tokens are never logged.
    """
    return IdentitySettings(
        source_tokens=_identity_source_tokens(),
        max_body_bytes=_env_int(
            "ORCH_IDENTITY_MAX_BODY_BYTES", DEFAULT_IDENTITY_MAX_BODY_BYTES, minimum=1
        ),
    )


# =========================================================================== #
# Cross-module automation-rules engine configuration (O-011, ADR-0011) — ADDITIVE,
# STANDALONE (not nested in CoordinationSettings — the automation engine has no
# registry/SSRF/health dependency; it reuses DistributionSettings directly, resolved
# separately at the app/ingest-router call site). Resolved NON-FATALLY: absence is not
# fatal. `enabled` DEFAULTS TO FALSE — this is new AUTONOMOUS behavior (a matched rule
# re-drives an O-004 policy distribution without further human action), so it ships OFF
# by default: no existing deployment silently starts auto-triggering distributions merely
# by upgrading. An operator opts in explicitly via ORCH_AUTOMATION_ENABLED=1.
# =========================================================================== #

#: Default per-tenant automation_rules cap (bounds worst-case per-event rule-evaluation
#: cost — enforced at rule-creation time, not at evaluation time).
DEFAULT_AUTOMATION_MAX_RULES_PER_TENANT: int = 20


@dataclass(frozen=True, slots=True)
class AutomationSettings:
    """Resolved cross-module automation-rules engine configuration (O-011, ADR-0011).

    enabled is the master switch (default False — conservative; see module docstring
    above). max_rules_per_tenant bounds the per-tenant automation_rules table (enforced
    at POST /v1/automation/rules time as a 422 `rule_limit_exceeded`, never at evaluation
    time), which in turn bounds the cost of evaluating rules against every accepted
    ingest event.
    """

    enabled: bool
    max_rules_per_tenant: int


def get_automation_settings() -> AutomationSettings:
    """Resolve automation-engine settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_AUTOMATION_ENABLED               master switch (default false — see the
                                            module-level comment on why the default is
                                            conservative).
      ORCH_AUTOMATION_MAX_RULES_PER_TENANT  per-tenant automation_rules cap (default 20,
                                            >= 1).
    """
    return AutomationSettings(
        enabled=_env_bool("ORCH_AUTOMATION_ENABLED"),
        max_rules_per_tenant=_env_int(
            "ORCH_AUTOMATION_MAX_RULES_PER_TENANT",
            DEFAULT_AUTOMATION_MAX_RULES_PER_TENANT,
            minimum=1,
        ),
    )


# =========================================================================== #
# Agent-messaging + shared-state-store configuration (O-012, ADR-0012) — ADDITIVE,
# STANDALONE (not nested in CoordinationSettings — messaging has no registry/SSRF/health
# dependency; it reuses the EXISTING `require_tenant_principal` credential, resolved
# separately at the app/router call site, exactly like AutomationSettings). Resolved
# NON-FATALLY: absence is not fatal. UNLIKE O-011's automation engine, there is NO master
# enable/disable switch here — sending a message or writing state is ordinary
# CALLER-INITIATED CRUD gated by the same `require_tenant_principal` credential every
# other tenant-write seam already requires (e.g. POST /v1/policies/distributions, POST
# /v1/automation/rules), not new AUTONOMOUS behavior triggered without an interactive
# caller. A default-off switch would mirror O-011's form without its underlying reasoning.
# =========================================================================== #

#: Default request-body size cap (bytes) for one agent_messages.body.
DEFAULT_MESSAGING_MAX_BODY_BYTES: int = 16384

#: Default request-body size cap (bytes) for one agent_state.state_value.
DEFAULT_MESSAGING_MAX_STATE_VALUE_BYTES: int = 16384

#: Default hard ceiling on GET /v1/messaging/inbox/... `limit` (the request's own limit is
#: clamped to this, mirroring every other cursor-paginated read's _MAX_LIMIT).
DEFAULT_MESSAGING_MAX_INBOX_PAGE_SIZE: int = 200

#: Default per-tenant cap on total agent_messages row count (security-auditor follow-up:
#: bounds unbounded per-tenant table growth, a cross-tenant AVAILABILITY concern on the
#: single shared Postgres instance — mirrors ORCH_AUTOMATION_MAX_RULES_PER_TENANT).
DEFAULT_MESSAGING_MAX_MESSAGES_PER_TENANT: int = 100000

#: Default per-tenant cap on distinct agent_state key count (same reasoning as above,
#: applied to the shared-state-store table instead of the mailbox table).
DEFAULT_MESSAGING_MAX_STATE_KEYS_PER_TENANT: int = 10000


@dataclass(frozen=True, slots=True)
class MessagingSettings:
    """Resolved agent-messaging + shared-state-store configuration (O-012, ADR-0012).

    No master enable/disable switch (see the module-level comment above for why —
    contrast with AutomationSettings.enabled). max_message_body_bytes and
    max_state_value_bytes bound the two opaque JSON payloads this seam ever persists;
    max_inbox_page_size is the hard ceiling GET /v1/messaging/inbox/... clamps its own
    `limit` query param to. max_messages_per_tenant and max_state_keys_per_tenant are
    per-tenant TOTAL ROW/KEY COUNT caps (security-auditor follow-up, mirrors
    AutomationSettings.max_rules_per_tenant) — they bound unbounded per-tenant table
    growth, a cross-tenant availability concern on the single shared Postgres instance;
    they do NOT bound the send/write RATE (see ADR-0012 Residual risk).
    """

    max_message_body_bytes: int
    max_state_value_bytes: int
    max_inbox_page_size: int
    max_messages_per_tenant: int
    max_state_keys_per_tenant: int


def get_messaging_settings() -> MessagingSettings:
    """Resolve agent-messaging settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_MESSAGING_MAX_BODY_BYTES        agent_messages.body size cap in bytes
                                           (default 16384, >= 1).
      ORCH_MESSAGING_MAX_STATE_VALUE_BYTES  agent_state.state_value size cap in bytes
                                           (default 16384, >= 1).
      ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE    hard ceiling on the inbox read's `limit`
                                           query param (default 200, >= 1).
      ORCH_MESSAGING_MAX_MESSAGES_PER_TENANT   per-tenant agent_messages row-count cap
                                           (default 100000, >= 1).
      ORCH_MESSAGING_MAX_STATE_KEYS_PER_TENANT  per-tenant agent_state distinct-key-count
                                           cap (default 10000, >= 1).
    """
    return MessagingSettings(
        max_message_body_bytes=_env_int(
            "ORCH_MESSAGING_MAX_BODY_BYTES", DEFAULT_MESSAGING_MAX_BODY_BYTES, minimum=1
        ),
        max_state_value_bytes=_env_int(
            "ORCH_MESSAGING_MAX_STATE_VALUE_BYTES",
            DEFAULT_MESSAGING_MAX_STATE_VALUE_BYTES,
            minimum=1,
        ),
        max_inbox_page_size=_env_int(
            "ORCH_MESSAGING_MAX_INBOX_PAGE_SIZE",
            DEFAULT_MESSAGING_MAX_INBOX_PAGE_SIZE,
            minimum=1,
        ),
        max_messages_per_tenant=_env_int(
            "ORCH_MESSAGING_MAX_MESSAGES_PER_TENANT",
            DEFAULT_MESSAGING_MAX_MESSAGES_PER_TENANT,
            minimum=1,
        ),
        max_state_keys_per_tenant=_env_int(
            "ORCH_MESSAGING_MAX_STATE_KEYS_PER_TENANT",
            DEFAULT_MESSAGING_MAX_STATE_KEYS_PER_TENANT,
            minimum=1,
        ),
    )


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
        relay=get_relay_settings(),
    )


# =========================================================================== #
# Third-party external gateway configuration (O-013, ADR-0013) — ADDITIVE, STANDALONE
# (not nested in CoordinationSettings — the gateway's key-management endpoints reuse
# CoordinationSettings.admin_token at the router call site directly, exactly like the
# admin API (O-007) does, rather than duplicating it here). UNLIKE MessagingSettings,
# `enabled` IS a master switch here (default False): the third-party read endpoint is the
# Orchestrator's first surface intended for a credential OTHER than an internal product
# or tenant service token, so an unconfigured deployment must not silently expose it
# merely by upgrading. Key issuance/revocation (operator-only, ORCH_ADMIN_TOKEN-gated)
# is NOT gated by `enabled` — an operator may provision keys ahead of flipping the switch,
# mirroring how POST /v1/automation/rules works regardless of ORCH_AUTOMATION_ENABLED.
# =========================================================================== #

#: Default per-key rate limit assigned at issuance when the request omits one.
DEFAULT_EXTERNAL_GATEWAY_RATE_LIMIT_PER_MINUTE: int = 60
#: Ceiling an operator may set for a single key's rate limit at issuance.
DEFAULT_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE: int = 6000
#: Per-tenant cap on total third_party_api_keys rows (bounds unbounded growth on the
#: shared, non-RLS, operator-global table).
DEFAULT_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT: int = 20


@dataclass(frozen=True, slots=True)
class ExternalGatewaySettings:
    """Resolved third-party external-gateway configuration (O-013, ADR-0013).

    `enabled` is the master switch (default False — see the module-level comment above).
    `default_rate_limit_per_minute` seeds a new key's limit when the issuance request
    omits `rate_limit_per_minute`. `max_rate_limit_per_minute` is the ceiling an operator
    may configure for any single key. `max_keys_per_tenant` bounds the per-tenant
    third_party_api_keys row count (enforced at issuance time as a 422
    `key_limit_exceeded`, never at request time).
    """

    enabled: bool
    default_rate_limit_per_minute: int
    max_rate_limit_per_minute: int
    max_keys_per_tenant: int


def get_external_gateway_settings() -> ExternalGatewaySettings:
    """Resolve external-gateway settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_EXTERNAL_GATEWAY_ENABLED                      master switch (default false).
      ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE default per-key rate limit
                                                          (default 60, >= 1).
      ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE     per-key rate-limit ceiling
                                                          (default 6000, >= 1).
      ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT           per-tenant key-count cap
                                                          (default 20, >= 1).
    """
    return ExternalGatewaySettings(
        enabled=_env_bool("ORCH_EXTERNAL_GATEWAY_ENABLED"),
        default_rate_limit_per_minute=_env_int(
            "ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE",
            DEFAULT_EXTERNAL_GATEWAY_RATE_LIMIT_PER_MINUTE,
            minimum=1,
        ),
        max_rate_limit_per_minute=_env_int(
            "ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE",
            DEFAULT_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE,
            minimum=1,
        ),
        max_keys_per_tenant=_env_int(
            "ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT",
            DEFAULT_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT,
            minimum=1,
        ),
    )


# =========================================================================== #
# Command center + guarded distribution rollback (O-014, ADR-0014) — ADDITIVE,
# STANDALONE. The command-center summary and the rollback action both reuse the EXISTING
# operator credential (CoordinationSettings.admin_token) at the router call site — no new
# trust root. No master enable/disable switch: the summary is read-only, and the rollback
# action already requires the operator bearer PLUS an explicit per-call (tenant_id,
# policy_id) target — there is no autonomous trigger to gate (see ADR-0014 Fork B).
# =========================================================================== #

#: Default lookback window (hours) the command-center summary aggregates over.
DEFAULT_COMMAND_CENTER_LOOKBACK_HOURS: int = 24


@dataclass(frozen=True, slots=True)
class CommandCenterSettings:
    """Resolved command-center configuration (O-014, ADR-0014).

    lookback_hours bounds the window `GET /v1/admin/command-center/summary` aggregates
    distribution/automation/external-gateway/ingest counts over — a fixed, bounded scan,
    never an unbounded full-table COUNT.
    """

    lookback_hours: int


def get_command_center_settings() -> CommandCenterSettings:
    """Resolve command-center settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_COMMAND_CENTER_LOOKBACK_HOURS  summary aggregation window in hours
                                         (default 24, >= 1).
    """
    return CommandCenterSettings(
        lookback_hours=_env_int(
            "ORCH_COMMAND_CENTER_LOOKBACK_HOURS",
            DEFAULT_COMMAND_CENTER_LOOKBACK_HOURS,
            minimum=1,
        ),
    )


# =========================================================================== #
# Predictive scaling — ingest-traffic current-rate projection (O-015, ADR-0015) —
# ADDITIVE, STANDALONE. Reuses the EXISTING operator credential
# (CoordinationSettings.admin_token) at the router call site — no new trust root. No
# master enable/disable switch: this is a pure read, and it takes no autoscaling action
# of any kind (there is nothing to gate — see ADR-0015 Fork A).
# =========================================================================== #

#: Default bucket size (hours) for the current/previous traffic windows.
DEFAULT_PREDICTIVE_SCALING_WINDOW_HOURS: int = 1
#: Default projection horizon (hours) the forecast holds the current rate over.
DEFAULT_PREDICTIVE_SCALING_HORIZON_HOURS: int = 24
#: Default current/previous rate ratio at or above which spike_detected is true.
DEFAULT_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD: float = 2.0


@dataclass(frozen=True, slots=True)
class PredictiveScalingSettings:
    """Resolved predictive-scaling configuration (O-015, ADR-0015).

    window_hours bounds the size of the two adjacent (current, previous) ingest-count
    buckets the forecast compares. horizon_hours is how far forward the CURRENT window's
    observed rate is held constant and projected (`current_rate_projection_v1` — mirrors
    Delta's D-011 ADR-0011 Fork 1 exactly, ecosystem-wide method-name consistency).
    spike_ratio_threshold is the current/previous rate ratio at or above which
    `spike_detected` is true; a previous window with zero events cannot compute a ratio
    at all (`insufficient_data: true`, never a divide-by-zero or a fabricated verdict).
    """

    window_hours: int
    horizon_hours: int
    spike_ratio_threshold: float


def get_predictive_scaling_settings() -> PredictiveScalingSettings:
    """Resolve predictive-scaling settings from the environment (NON-FATAL on absence).

    Env vars:
      ORCH_PREDICTIVE_SCALING_WINDOW_HOURS          current/previous bucket size in hours
                                                    (default 1, >= 1).
      ORCH_PREDICTIVE_SCALING_HORIZON_HOURS         projection horizon in hours
                                                    (default 24, >= 1).
      ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD current/previous rate ratio that
                                                    triggers spike_detected (default 2.0,
                                                    >= 1.0 — a ratio below 1.0 would flag
                                                    a DECREASE as a "spike").
    """
    return PredictiveScalingSettings(
        window_hours=_env_int(
            "ORCH_PREDICTIVE_SCALING_WINDOW_HOURS",
            DEFAULT_PREDICTIVE_SCALING_WINDOW_HOURS,
            minimum=1,
        ),
        horizon_hours=_env_int(
            "ORCH_PREDICTIVE_SCALING_HORIZON_HOURS",
            DEFAULT_PREDICTIVE_SCALING_HORIZON_HOURS,
            minimum=1,
        ),
        spike_ratio_threshold=_env_float(
            "ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD",
            DEFAULT_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD,
            minimum=1.0,
        ),
    )
