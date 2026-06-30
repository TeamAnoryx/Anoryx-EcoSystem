"""SSRF endpoint validation (O-005, ADR-0005) — the load-bearing security property.

A data-driven Sentinel registry maps sentinel_id -> endpoint, and those endpoints feed
directly into outbound httpx calls (health probes + policy distribution). An unvalidated
registry is therefore an SSRF / amplification vector: a malicious or mistaken endpoint could
direct the Orchestrator at internal services or cloud metadata (169.254.169.254). This module
is the single gate. By default ONLY public https endpoints pass; private / loopback /
link-local / multicast / reserved / unspecified destinations are rejected unless the operator
explicitly allowlists the host (ORCH_REGISTRY_ENDPOINT_ALLOWLIST). DNS-rebinding is defended
by resolving the host and rejecting if ANY resolved address is blocked.

validate_endpoint() MUST be called at registration AND re-validated before every outbound use
(health poll + push target build) — the stored endpoint is never trusted blindly, because the
allowlist may change and a name may rebind to a private address between registration and use.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

# Schemes the registry permits at all. http is gated further (allowlisted host + allow_http).
_ALLOWED_SCHEMES = frozenset({"https", "http"})


class EndpointValidationError(ValueError):
    """Raised when an endpoint fails SSRF validation. `reason` is a short audit code.

    `reason` is a stable machine code (e.g. "blocked_private_ip", "scheme_not_allowed") suitable
    for the registry-mutation audit log's error_reason field; it never carries the endpoint value
    or any secret.
    """

    def __init__(self, reason: str, message: str | None = None) -> None:
        self.reason = reason
        super().__init__(message or reason)


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True iff *ip* is in a range the Orchestrator must never make an outbound call to.

    Explicitly ORs every dangerous flag (rather than relying on is_private alone) so the rule is
    stable across Python versions and covers loopback, RFC1918, link-local (incl. the
    169.254.169.254 cloud-metadata address), carrier-grade NAT shared space, multicast, reserved,
    and the unspecified address.
    """
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return the IP addresses *host* denotes — the literal itself, or every getaddrinfo result.

    Raises EndpointValidationError("dns_resolution_failed") if a hostname cannot be resolved (a
    fail-closed posture: an endpoint we cannot resolve is not admitted). For DNS-rebinding
    defense the caller checks EVERY returned address.
    """
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass  # not an IP literal — resolve as a hostname below.

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise EndpointValidationError(
            "dns_resolution_failed", "endpoint host could not be resolved"
        ) from exc

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        candidate = info[4][0]
        try:
            ips.append(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    if not ips:
        raise EndpointValidationError(
            "dns_resolution_failed", "endpoint host resolved to no usable addresses"
        )
    return ips


def validate_endpoint(url: str, *, allowlist: frozenset[str], allow_http: bool) -> str:
    """Validate an endpoint URL for outbound use. Returns the normalized URL, or raises.

    allowlist is a set of exact `host` or `host:port` entries (lowercased). An allowlisted host
    bypasses the private-IP block (the operator vouched for it) and is the ONLY way an http
    endpoint passes (and only when allow_http is also set). With an empty allowlist, only a
    public https endpoint passes — fail-closed.
    """
    if not url or not url.strip():
        raise EndpointValidationError("empty_endpoint", "endpoint is empty")
    raw = url.strip()

    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise EndpointValidationError("malformed_url", "endpoint is not a valid URL") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise EndpointValidationError("scheme_not_allowed", f"scheme {scheme!r} is not allowed")
    if parts.username or parts.password:
        raise EndpointValidationError("embedded_credentials", "endpoint must not embed credentials")
    if parts.fragment:
        raise EndpointValidationError(
            "fragment_not_allowed", "endpoint must not contain a fragment"
        )

    host = parts.hostname
    if not host:
        raise EndpointValidationError("missing_host", "endpoint has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise EndpointValidationError("malformed_url", "endpoint has an invalid port") from exc

    host_l = host.lower()
    hostport_l = f"{host_l}:{port}" if port is not None else None
    allowlisted = host_l in allowlist or (hostport_l is not None and hostport_l in allowlist)

    if scheme == "http" and not (allow_http and allowlisted):
        raise EndpointValidationError(
            "http_not_allowed",
            "http requires an allowlisted host and ORCH_REGISTRY_ALLOW_HTTP",
        )

    # Resolve + check every address (DNS-rebinding defense). An allowlisted host is exempt from
    # the private-IP block — the operator explicitly vouched for it (e.g. the loopback test shim).
    for ip in _resolve_ips(host_l):
        if _is_blocked_ip(ip) and not allowlisted:
            raise EndpointValidationError(
                "blocked_private_ip", "endpoint resolves to a blocked (private/loopback) address"
            )

    return raw
