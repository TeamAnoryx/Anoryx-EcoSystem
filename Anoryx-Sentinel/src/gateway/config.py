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

from pydantic import field_validator, model_validator
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
        Anthropic requires anthropic_api_key. Bedrock requires all three AWS
        fields. A provider not in this set is fail-closed unavailable for every
        tenant regardless of any routing policy listing it (ADR-0008 §3 / §10).
        """
        providers = {"openai"}
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
