"""Unit tests for the F-026 MCP server-registration URL guard (ADR-0032).

Mirrors tests/orchestration/webhooks/test_url_guard.py's discipline exactly:
every test uses an injected resolver (ResolverFn) so no network I/O occurs —
this is the module that decides whether Sentinel will ever connect to an
operator-supplied external URL, so its tests must not depend on real DNS.
"""

from __future__ import annotations

import socket

from mcp_gateway.url_guard import validate_mcp_server_url


def _resolver_for(ip: str):
    def resolver(host: str, port: int) -> list:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (ip, port))]

    return resolver


_resolver_public = _resolver_for("93.184.216.34")  # example.com's real public IP


def test_public_https_url_allowed():
    result = validate_mcp_server_url("https://mcp.example.com/rpc", resolver=_resolver_public)
    assert result.allowed is True
    assert result.hostname == "mcp.example.com"
    assert result.pinned_ip == "93.184.216.34"


def test_loopback_denied():
    result = validate_mcp_server_url(
        "https://internal-mcp/rpc", resolver=_resolver_for("127.0.0.1")
    )
    assert result.allowed is False


def test_link_local_metadata_endpoint_denied():
    result = validate_mcp_server_url(
        "https://169.254.169.254/rpc", resolver=_resolver_for("169.254.169.254")
    )
    assert result.allowed is False


def test_private_range_denied():
    result = validate_mcp_server_url("https://internal-mcp/rpc", resolver=_resolver_for("10.0.0.5"))
    assert result.allowed is False


def test_http_scheme_denied():
    result = validate_mcp_server_url("http://mcp.example.com/rpc", resolver=_resolver_public)
    assert result.allowed is False


def test_non_default_port_denied_by_default_allowlist():
    # mcp_allowed_ports defaults to {443} — a non-standard port is denied
    # even on an otherwise-public HTTPS host.
    result = validate_mcp_server_url("https://mcp.example.com:8443/rpc", resolver=_resolver_public)
    assert result.allowed is False


def test_dns_rebind_defeated_by_resolve_and_pin():
    """A synthetic resolver returning a private IP for a plausible-looking
    public hostname must still be denied — proves we don't trust the
    hostname string, only the resolved IP (the resolve-and-pin contract)."""
    result = validate_mcp_server_url(
        "https://looks-public.example.com/rpc", resolver=_resolver_for("10.1.2.3")
    )
    assert result.allowed is False
