"""F-026 MCP-gateway configuration (ADR-0032).

Reads env via pydantic-settings, matching the DrSettings/BulkSettings
convention (no env prefix beyond the field name).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class McpGatewaySettings(BaseSettings):
    """F-026 MCP-gateway runtime configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Ports permitted for a registered MCP server's URL (SSRF guard, ADR-0023 §7
    # hardening point 3 already enforces https:// scheme regardless of port).
    # Default: HTTPS-standard only. Widen for operators running self-hosted MCP
    # servers on non-standard ports — the IP-classification/resolve-and-pin
    # protections still apply at any allowed port.
    mcp_allowed_ports: frozenset[int] = frozenset({443})


@lru_cache(maxsize=1)
def get_mcp_gateway_settings() -> McpGatewaySettings:
    """Cached McpGatewaySettings accessor (one instance per process)."""
    return McpGatewaySettings()


def _reset_mcp_gateway_settings_for_testing() -> None:
    """Clear the cached settings (test helper only)."""
    get_mcp_gateway_settings.cache_clear()
