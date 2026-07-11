"""Gateway configuration (F-004, extended F-006).

Reads environment variables via pydantic-settings. Required values with no safe
default fail loud at startup — a missing required secret raises before the server
accepts traffic (ADR-0006 Decision 9).

NEVER log (secrets — threat #1, ADR-0008 §10):
  - DATABASE_URL, APP_DATABASE_URL, SENTINEL_KEY_SECRET
  - ANTHROPIC_API_KEY                      (F-006 provider secret)
  - AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (F-006 Bedrock SigV4 secrets)
A structlog processor (gateway/logging.py) drops any log key matching
*_API_KEY / *_SECRET* / AWS_* as a defense-in-depth backstop.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    """Gateway runtime configuration. Fail-loud on missing required fields."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Required (no default; startup fails if absent) ---
    upstream_base_url: str
    database_url: str
    app_database_url: str
    sentinel_key_secret: str

    # --- Optional with sane defaults ---
    request_timeout_seconds: float = 60.0
    stream_timeout_seconds: float = 30.0
    max_body_bytes: int = 1_048_576  # 1 MiB — MUST match contract cap
    max_tokens_per_request: int = 131_072  # hard ceiling; contract max_tokens bound
    rate_limit_rpm: int = 600  # 600 requests / 60 s sliding window
    rate_limit_burst: int = 60  # short-term burst bound within the window
    max_concurrent_streams_per_tenant: int = 20
    # CORS: default-deny. Explicit allowlist only. Never "*" with credentials.
    cors_allowed_origins: list[str] = []

    # --- F-022 multi-region posture (ADR-0028 D2; H1 remediation) ---
    # This region's role. A "passive" region is a replication standby: it MUST NOT
    # serve governed / audit-generating traffic, because every governed request
    # appends to its LOCAL events_audit_log whose sequence_number is a per-DB
    # bigserial that logical replication does not carry — a local write forks the
    # tamper-evident hash chain (F-022 audit H1). Enforced fail-closed by
    # gateway/middleware/region_guard.py. Default "active" so single-region and
    # unset deployments serve normally; an invalid value fails startup (fail-loud)
    # rather than risk an unenforced posture.
    region_role: str = Field(default="active", validation_alias="SENTINEL_REGION_ROLE")

    @field_validator("region_role")
    @classmethod
    def _validate_region_role(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in ("active", "passive"):
            raise ValueError("SENTINEL_REGION_ROLE must be 'active' or 'passive'")
        return normalized

    # --- F-009 Redis-backed rate limiting (ADR-0011) ---
    # redis_url keeps its default so γ (fallback to in-process) works without
    # Redis configured. A required field would contradict failure mode γ.
    redis_url: str = "redis://localhost:6379/0"
    # R10: connect timeout 2.0 s; socket read/write timeout 1.0 s (hardcoded in redis_client.py).
    redis_connection_timeout: float = 2.0
    redis_pool_size: int = 10

    # --- F-023 policy-eval cache (ADR-0029) ---
    # Short TTL is a fail-safe backstop only — the primary invalidation path is
    # an immediate per-tenant version bump on every accepted F-008 policy write
    # (policy/eval_cache.py). 0 disables caching (every request re-evaluates).
    policy_eval_cache_ttl_seconds: float = 5.0

    # --- F-009 Observability (ADR-0011 §4-§5) ---
    # Per-tenant metrics gate: default False to avoid linear cardinality growth
    # with tenant count. Enable only when operationally needed.
    # WARNING: setting this to True increases Prometheus storage cost linearly
    # with tenant count; enable only when operationally needed.
    enable_per_tenant_metrics: bool = False
    metrics_path: str = "/metrics"
    enable_otel: bool = True

    # --- F-006 multi-provider router (ADR-0008 §10) ---
    # Provider keys are SECRETS — never logged (see module docstring + logging.py).
    # OpenAI uses the existing required upstream_base_url; Anthropic + Bedrock are
    # opt-in. A provider with no configured key is NOT initialised and is treated
    # as not-allowed for every tenant (fail-closed, ADR-0008 §3 / §10).
    anthropic_api_key: str | None = None  # secret
    anthropic_base_url: str = "https://api.anthropic.com"  # config-pinned (SSRF defense)
    aws_region: str | None = None  # pins SigV4 region + Bedrock base_url
    aws_access_key_id: str | None = None  # secret
    aws_secret_access_key: str | None = None  # secret
    router_max_fallbacks: int = 2  # total attempts = 1 + this; validated 0..8
    router_default_providers: list[str] = ["openai", "anthropic", "bedrock"]
    # Injected when a client omits max_tokens for Anthropic (which requires it).
    router_anthropic_default_max_tokens: int = 1024

    # --- F-027 provider key vaulting (ADR-0033) ---
    # "env" (default) is byte-identical to pre-F-027 behavior: raw secrets
    # above. "vault"/"kms" mean anthropic_api_key/aws_* are intentionally left
    # unset — real credentials come from gateway/keyvault/ at registry init +
    # periodic refresh (gateway/main.py). See KeyVaultSettings for backend config.
    keyvault_backend: Literal["env", "vault", "kms"] = "env"

    @field_validator("max_body_bytes")
    @classmethod
    def _validate_max_body_bytes(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("max_body_bytes must be > 0")
        return v

    @field_validator("max_tokens_per_request")
    @classmethod
    def _validate_max_tokens(cls, v: int) -> int:
        # Contract max_tokens ceiling is 131072; configuring above it is a divergence.
        if v <= 0 or v > 131_072:
            raise ValueError("max_tokens_per_request must be in [1, 131072]")
        return v

    @field_validator("rate_limit_rpm")
    @classmethod
    def _validate_rpm(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("rate_limit_rpm must be > 0")
        return v

    @field_validator("router_max_fallbacks")
    @classmethod
    def _validate_router_max_fallbacks(cls, v: int) -> int:
        # ADR-0008 §10: bound the fallback chain length independent of provider count.
        if v < 0 or v > 8:
            raise ValueError("router_max_fallbacks must be in [0, 8]")
        return v

    @field_validator("router_anthropic_default_max_tokens")
    @classmethod
    def _validate_anthropic_default_max_tokens(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("router_anthropic_default_max_tokens must be > 0")
        return v

    @model_validator(mode="after")
    def _validate_router_consistency(self) -> "GatewaySettings":
        # ADR-0008 §10 fail-loud: a half-configured Bedrock provider is a
        # misconfiguration. If ANY AWS field is set, ALL three must be set.
        aws_fields = (self.aws_region, self.aws_access_key_id, self.aws_secret_access_key)
        if any(aws_fields) and not all(aws_fields):
            raise ValueError(
                "Bedrock is half-configured: AWS_REGION, AWS_ACCESS_KEY_ID, and "
                "AWS_SECRET_ACCESS_KEY must ALL be set together (or all unset). "
                "A half-configured provider is a misconfiguration (ADR-0008 §10)."
            )
        # The Anthropic default-max-tokens injection must not exceed the hard cap.
        if self.router_anthropic_default_max_tokens > self.max_tokens_per_request:
            raise ValueError(
                "router_anthropic_default_max_tokens must be <= max_tokens_per_request"
            )
        # router_default_providers must be a subset of the known providers.
        known = {"openai", "anthropic", "bedrock"}
        unknown = set(self.router_default_providers) - known
        if unknown:
            raise ValueError(f"router_default_providers has unknown providers: {sorted(unknown)}")
        return self

    def configured_providers(self) -> set[str]:
        """Return the set of providers that have credentials configured.

        OpenAI is always configured (it uses the required upstream_base_url).

        keyvault_backend="env" (default): Anthropic requires anthropic_api_key;
        Bedrock requires all three AWS fields — exactly pre-F-027 behavior.

        keyvault_backend="vault"/"kms": raw env secrets are intentionally
        unset, so "configured" instead means "declared in
        router_default_providers" — the real credential presence/absence is
        checked at registry init time via gateway/keyvault/ (fail-closed there
        too: a provider whose vault/kms fetch fails is not initialised).

        A provider not in this set is fail-closed unavailable for every
        tenant regardless of any routing policy listing it (ADR-0008 §3/§10).
        """
        providers = {"openai"}
        if self.keyvault_backend != "env":
            for name in ("anthropic", "bedrock"):
                if name in self.router_default_providers:
                    providers.add(name)
            return providers
        if self.anthropic_api_key:
            providers.add("anthropic")
        if self.aws_region and self.aws_access_key_id and self.aws_secret_access_key:
            providers.add("bedrock")
        return providers


_settings: GatewaySettings | None = None


def get_settings() -> GatewaySettings:
    """Return the cached GatewaySettings singleton.

    Instantiation triggers pydantic-settings validation; missing required
    fields raise a ValidationError before any request is processed.
    """
    global _settings
    if _settings is None:
        _settings = GatewaySettings()
    return _settings


def _reset_settings() -> None:
    """Reset the cached settings singleton (test helper only)."""
    global _settings
    _settings = None
