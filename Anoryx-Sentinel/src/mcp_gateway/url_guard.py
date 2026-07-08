"""SSRF guard for MCP server registration (F-026, ADR-0032).

Reuses orchestration.webhooks.url_guard.check_url VERBATIM (F-020, ADR-0023
§7) rather than reimplementing SSRF defenses — the exact same
deny-by-default IP classification, resolve-and-pin, TLS-only/no-redirect,
and fail-closed posture that already gates every outbound webhook target
gates every registered MCP server URL. This is the SAME class of problem
(an admin-supplied external URL a Sentinel-controlled process must not blindly
trust or connect to) — see admin/webhooks.py::_guard_target_url for the
precedent this mirrors.

Called at MCP-server REGISTRATION time (mcp_gateway/allowlist.py, before any
row is persisted) — mirrors "SSRF guard BEFORE any persistence" from
admin/webhooks.py. A future live proxy (docs/followups/
f-026-mcp-proxy-endpoint.md) MUST re-validate at connect time too (resolve-
and-pin defeats only the window between validate-and-connect, not a URL that
starts safe and is later repointed via DNS — the same TOCTOU note
orchestration.webhooks.url_guard's own docstring makes).
"""

from __future__ import annotations

from mcp_gateway.config import get_mcp_gateway_settings
from orchestration.webhooks.url_guard import GuardResult, ResolverFn, _default_resolver, check_url


def validate_mcp_server_url(url: str, *, resolver: ResolverFn = _default_resolver) -> GuardResult:
    """Validate *url* for safe registration as an allow-listed MCP server.

    resolver is a dependency-injection seam (default: socket.getaddrinfo,
    matching check_url's own convention) — tests inject a synthetic resolver
    so SSRF-guard tests never depend on real network/DNS (mirrors
    tests/orchestration/webhooks/test_url_guard.py's own discipline exactly).

    Returns a GuardResult (.allowed / .reason / .pinned_ip / .hostname) — the
    caller decides what to do with a deny (mcp_gateway/allowlist.py raises
    ServerUrlRejected; a future HTTP admin route would map it to 422, exactly
    as admin/webhooks.py::_guard_target_url does today).
    """
    settings = get_mcp_gateway_settings()
    return check_url(url, allowed_ports=settings.mcp_allowed_ports, resolver=resolver)
