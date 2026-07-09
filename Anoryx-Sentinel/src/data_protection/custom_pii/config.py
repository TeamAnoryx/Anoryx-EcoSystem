"""CustomPiiSettings (F-028, ADR-0034)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CustomPiiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Master gate for the custom-PII hook. Default ON, but a tenant with zero
    # registered patterns incurs only one (cached) empty DB read — see loader.py.
    custom_pii_enabled: bool = True

    # Default action when a pattern has no per-pattern override: mask|tokenize|block.
    custom_pii_action: str = "mask"

    # Hot-reload cache TTL. A pattern change lands in a live gateway within this
    # window (bounded-lag, same rationale as F-027's keyvault cache).
    custom_pii_cache_ttl_seconds: float = 30.0

    # --- Security bounds on client-supplied regex (ReDoS defense-in-depth) ---
    # Max active patterns per tenant — an unbounded set is an unbounded
    # per-request matching cost.
    custom_pii_max_patterns_per_tenant: int = 50
    # Max length of a single pattern's regex text.
    custom_pii_max_pattern_length: int = 512
    # Per-match wall-clock timeout (seconds) passed to regex.finditer — the hard
    # ReDoS backstop even if a catastrophic pattern slips past registration
    # validation.
    custom_pii_match_timeout_seconds: float = 0.25
    # Max chars of content scanned per request (latency cap, mirrors F-005's
    # max_pii_inspect_chars).
    custom_pii_max_inspect_chars: int = 50_000

    @model_validator(mode="after")
    def _validate(self) -> "CustomPiiSettings":
        if self.custom_pii_action not in ("mask", "tokenize", "block"):
            raise ValueError(
                f"custom_pii_action must be mask|tokenize|block, got {self.custom_pii_action!r}"
            )
        if self.custom_pii_cache_ttl_seconds <= 0:
            raise ValueError("custom_pii_cache_ttl_seconds must be > 0")
        if self.custom_pii_max_patterns_per_tenant <= 0:
            raise ValueError("custom_pii_max_patterns_per_tenant must be > 0")
        if self.custom_pii_max_pattern_length <= 0:
            raise ValueError("custom_pii_max_pattern_length must be > 0")
        if self.custom_pii_match_timeout_seconds <= 0:
            raise ValueError("custom_pii_match_timeout_seconds must be > 0")
        if self.custom_pii_max_inspect_chars <= 0:
            raise ValueError("custom_pii_max_inspect_chars must be > 0")
        return self


@lru_cache
def get_custom_pii_settings() -> CustomPiiSettings:
    return CustomPiiSettings()


def _reset_custom_pii_settings_for_testing() -> None:
    get_custom_pii_settings.cache_clear()
