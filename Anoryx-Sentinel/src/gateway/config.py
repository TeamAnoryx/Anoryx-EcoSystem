"""Gateway configuration (F-004).

Reads environment variables via pydantic-settings. Required values with no safe
default fail loud at startup — a missing required secret raises before the server
accepts traffic (ADR-0006 Decision 9).

NEVER log DATABASE_URL, APP_DATABASE_URL, SENTINEL_KEY_SECRET, or any secret.
"""

from __future__ import annotations

from pydantic import field_validator
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
