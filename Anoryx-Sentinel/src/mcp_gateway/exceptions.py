"""F-026 MCP-gateway exceptions.

All errors derive from McpGatewayError. NEVER embed a raw server_url in an
exception message intended for external-facing surfaces beyond the operator
CLI (topology-safety mirrors the F-020 url_guard's own discipline) — the CLI
itself may print the URL back to the operator who supplied it, since that's
not a leak (they already know it).
"""

from __future__ import annotations


class McpGatewayError(Exception):
    """Base class for all F-026 MCP-gateway errors."""


class ServerUrlRejected(McpGatewayError):
    """A candidate MCP server URL failed the SSRF guard — rejected before any write."""


class InvalidServerName(McpGatewayError):
    """A supplied server name failed the naming convention (non-empty, bounded)."""
