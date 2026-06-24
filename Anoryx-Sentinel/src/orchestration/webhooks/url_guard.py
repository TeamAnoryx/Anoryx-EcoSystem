"""SSRF URL guard for outbound webhook delivery (F-020, ADR-0023 §7).

This module is the load-bearing SSRF control for F-020 — every outbound
webhook delivery POST goes through it. It implements the five hardening
points from ADR-0023 §7:

  1. Deny-by-default IP classification — block private/reserved/loopback/
     link-local/ULA/IPv4-mapped-IPv6/0.0.0.0 ranges; allow only
     publicly-routable addresses (vectors 1, 2, 7).

  2. Resolve-and-pin — resolve the target hostname ONCE, validate every
     resolved IP is public, then connect to the PINNED IP, defeating the
     TOCTOU / DNS-rebind window between validate-and-connect (vector 3).

  3. No redirects, TLS-only, port allowlist — `follow_redirects=False`,
     `https://` scheme only, ports restricted to the configured allowlist
     (default: 443 + Splunk HEC 8088) (vectors 4, 5, 6).

  4. Provider-templated hosts — Slack (hooks.slack.com) and Jira
     (*.atlassian.net) match known host-pattern allowlists, reducing the
     arbitrary-URL surface to Splunk/custom hosts, which still pass through
     the full strict guard (D2).

  5. Fail-open isolation — guard rejection is AUDITED and DROPPED; it never
     raises into or blocks the request path (D5/§4.1). This module returns a
     structured GuardResult; it is the CALLER'S responsibility to map a deny
     to failure_class='url_guard_rejected'.

Design notes:
  * `resolver` is a dependency-injection seam (default: socket.getaddrinfo).
    Tests pass a synthetic resolver to simulate DNS-rebind / private IPs
    without network access.
  * The pinned_ip is returned in GuardResult.pinned_ip so the httpx client
    can connect directly to the IP while setting Host/SNI to the original
    hostname (defeating DNS-rebind at connect time).
  * ipaddress.ip_address is used for all IP classification; no regex.

NEVER log: target URLs, raw IP addresses, or error details that could
leak infrastructure topology.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Provider host-pattern allowlists (ADR-0023 D2 / §7 hardening point 4)
# ---------------------------------------------------------------------------

# Slack incoming webhook host — exact match.
_SLACK_HOST_ALLOWLIST: frozenset[str] = frozenset({"hooks.slack.com"})

# Jira host pattern — *.atlassian.net (subdomain only, no port component).
_JIRA_HOST_PATTERN = re.compile(r"^[a-z0-9-]+\.atlassian\.net$", re.IGNORECASE)

# Splunk hosts are tenant-supplied and MUST pass the strict guard (D2).

# ---------------------------------------------------------------------------
# Failure reason slugs (maps to failure_class='url_guard_rejected')
# ---------------------------------------------------------------------------
_REASON_NOT_HTTPS = "scheme_not_https"
_REASON_PORT_NOT_ALLOWED = "port_not_allowed"
_REASON_HOST_EMPTY = "host_empty"
_REASON_PRIVATE_IP = "private_ip_resolved"
_REASON_RESOLVE_FAILED = "dns_resolve_failed"
_REASON_NO_PUBLIC_IP = "no_public_ip_resolved"


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GuardResult:
    """Outcome of a URL guard check.

    Fields
    ------
    allowed : bool
        True when the URL passes all checks; False otherwise.
    reason : str | None
        A bounded slug explaining the deny reason (never raw error text).
        None when allowed=True.
    pinned_ip : str | None
        When allowed=True, the first public IP address resolved for the host.
        The caller MUST connect to this IP directly (defeat DNS-rebind) while
        setting SNI/Host headers to the original hostname.
        None when allowed=False.
    hostname : str | None
        The original hostname extracted from the URL. Set on both allow and
        deny outcomes for audit purposes. NEVER an IP/URL — the host only.
    """

    allowed: bool
    reason: str | None
    pinned_ip: str | None
    hostname: str | None


# ---------------------------------------------------------------------------
# Default resolver (injectable)
# ---------------------------------------------------------------------------

# Type alias for the resolver callable.
# Signature mirrors socket.getaddrinfo(host, port) -> list of (family, ..., sockaddr).
ResolverFn = Callable[[str, int], list]


def _default_resolver(host: str, port: int) -> list:
    """Thin wrapper around socket.getaddrinfo for AF_INET + AF_INET6."""
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


# ---------------------------------------------------------------------------
# IP range classification
# ---------------------------------------------------------------------------


def _is_public_ip(addr_str: str) -> bool:
    """Return True if *addr_str* is a globally-routable public IP address.

    Denies all:
      - loopback (127.x.x.x / ::1)
      - private ranges (RFC 1918: 10/8, 172.16/12, 192.168/16)
      - link-local (169.254/16 / fe80::/10) — cloud metadata endpoint lives here
      - ULA / IPv6 ULA (fc00::/7)
      - IPv4-mapped IPv6 (::ffff:x.y.z.w where x.y.z.w is non-public)
      - unspecified / 0.0.0.0 / ::
      - multicast / loopback / reserved

    Uses Python's ipaddress module exclusively (no regex on IP addresses).
    """
    try:
        ip = ipaddress.ip_address(addr_str)
    except ValueError:
        # Unparseable address string — deny conservatively.
        return False

    # Deny the IPv4-mapped-IPv6 special case FIRST before the generic checks,
    # because is_global is True for some ::ffff: mapped private addresses in
    # older Python versions. We unwrap the mapped IPv4 and re-check it.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # Re-classify the embedded IPv4 address.
        return _is_public_ip(str(ip.ipv4_mapped))

    if ip.is_loopback:
        return False
    if ip.is_private:
        return False
    if ip.is_link_local:
        return False
    if ip.is_multicast:
        return False
    if ip.is_unspecified:  # 0.0.0.0 / ::
        return False
    if ip.is_reserved:
        return False

    # IPv6 ULA: fc00::/7 — Python's is_private covers this in 3.11+ but we
    # explicitly check for older compat.
    if isinstance(ip, ipaddress.IPv6Address):
        # ULA range: first octet 0xfc or 0xfd (fc00::/7).
        first_byte = (int(ip) >> 120) & 0xFF
        if first_byte in (0xFC, 0xFD):
            return False

    return ip.is_global


# ---------------------------------------------------------------------------
# Provider-pattern host checks (§7 hardening point 4)
# ---------------------------------------------------------------------------


def _is_slack_host(host: str) -> bool:
    return host.lower() in _SLACK_HOST_ALLOWLIST


def _is_jira_host(host: str) -> bool:
    return bool(_JIRA_HOST_PATTERN.match(host.lower()))


# ---------------------------------------------------------------------------
# Core guard function
# ---------------------------------------------------------------------------


def check_url(
    url: str,
    *,
    allowed_ports: frozenset[int] | None = None,
    resolver: ResolverFn = _default_resolver,
) -> GuardResult:
    """Validate *url* for safe outbound webhook delivery.

    Parameters
    ----------
    url:
        The target URL stored in webhook_config.target_url.
    allowed_ports:
        Ports permitted by the guard.  Defaults to {443, 8088}.
    resolver:
        DNS resolver callable — injectable for testing.  Default: socket.getaddrinfo.

    Returns
    -------
    GuardResult
        .allowed=True with a pinned_ip when the URL is safe to connect to.
        .allowed=False with a reason slug when the URL is denied.
    """
    if allowed_ports is None:
        from orchestration.webhooks.config import get_webhook_settings

        allowed_ports = get_webhook_settings().webhook_allowed_ports

    # --- Parse ---
    try:
        parsed = urlparse(url)
    except Exception:
        return GuardResult(allowed=False, reason=_REASON_HOST_EMPTY, pinned_ip=None, hostname=None)

    # --- Host extraction (needed before TEST-ONLY seam check) ---
    host = parsed.hostname or ""
    if not host:
        return GuardResult(allowed=False, reason=_REASON_HOST_EMPTY, pinned_ip=None, hostname=None)

    # urlparse returns None when no explicit port is in the URL; HTTPS default is 443.
    port = parsed.port if parsed.port is not None else 443

    # --- TEST-ONLY bypass seam (WEBHOOK_ALLOWED_TEST_HOSTS, DEFAULT EMPTY) ---
    # This is the ONLY guard bypass in this module.  It is reachable ONLY when
    # WEBHOOK_ALLOWED_TEST_HOSTS is explicitly set (default: empty frozenset).
    # In production this block is unreachable because the setting is never
    # populated.  Do NOT add any other bypass path.
    #
    # When the target host:port is in the test-host list we:
    #   (a) skip the IP-classification deny (allows loopback/private IPs), and
    #   (b) allow any scheme (including http) and any port,
    # so a real local HTTP sink (e.g. http://127.0.0.1:PORT) is reachable for
    # the V12 non-stubbed e2e test without touching any production guard path.
    #
    # REQUIRED FORMAT: entries MUST be "host:port" (e.g. "127.0.0.1:19876").
    # Bare host entries (without a port) are NOT accepted — a bare host would
    # wildcard the bypass across ALL ports on that host.  The port is always
    # known at this point (parsed from the URL or defaulted to 443 above).
    #
    # NOTE: this seam is checked BEFORE the scheme/port guards so that http:// test
    # sinks are reachable.  The entire block is a no-op when the frozenset is empty.
    from orchestration.webhooks.config import get_webhook_settings  # local import avoids circular

    _test_hosts = get_webhook_settings().webhook_allowed_test_hosts
    if _test_hosts:  # guard: frozenset() is falsy — branch never entered in prod
        # Always use "host:port" form — port is always defined here (URL or default 443).
        _host_key = f"{host}:{port}"
        if _host_key in _test_hosts:
            # TEST-ONLY: return allowed with the host itself as the "pinned_ip"
            # so the http client can connect directly.  The caller uses the original URL.
            return GuardResult(allowed=True, reason=None, pinned_ip=host, hostname=host)

    # --- Scheme check: HTTPS only (vector 5) ---
    if parsed.scheme.lower() != "https":
        return GuardResult(allowed=False, reason=_REASON_NOT_HTTPS, pinned_ip=None, hostname=host)

    # --- Port check (vector 6) ---
    if port not in allowed_ports:
        return GuardResult(
            allowed=False, reason=_REASON_PORT_NOT_ALLOWED, pinned_ip=None, hostname=host
        )

    # --- Provider-template gate for Slack/Jira (§7 hardening point 4) ---
    # The host-pattern allowlist gates WHICH hostnames are accepted as Slack/Jira
    # targets, but accepted hosts STILL pass through _strict_guard to validate that
    # every resolved IP is publicly routable and to obtain a pinned IP.
    #
    # The previous _resolve_pinned_ip shortcut was MED-severity: a split-horizon DNS
    # or compromised resolver returning a private IP for hooks.slack.com would have
    # passed the scheme+port checks and returned allowed=True with a private pinned_ip.
    # _strict_guard eliminates that gap: it denies if ANY resolved IP is non-public.
    if _is_slack_host(host) or _is_jira_host(host):
        return _strict_guard(host, port, resolver=resolver)

    # --- Full strict guard for Splunk / custom hosts ---
    return _strict_guard(host, port, resolver=resolver)


def _strict_guard(host: str, port: int, *, resolver: ResolverFn) -> GuardResult:
    """Full SSRF guard for Splunk / arbitrary-URL hosts.

    Resolves the host, validates EVERY resolved IP is public (deny if any is
    private), then returns the first public IP as the pinned connect address.
    """
    try:
        addrinfos = resolver(host, port)
    except Exception:
        # DNS failure — deny conservatively; never log the exception message
        # (could contain topology/host details).
        return GuardResult(
            allowed=False, reason=_REASON_RESOLVE_FAILED, pinned_ip=None, hostname=host
        )

    if not addrinfos:
        return GuardResult(
            allowed=False, reason=_REASON_NO_PUBLIC_IP, pinned_ip=None, hostname=host
        )

    first_public: str | None = None
    for info in addrinfos:
        # addrinfo tuple: (family, type, proto, canonname, sockaddr)
        # sockaddr for AF_INET:  (address, port)
        # sockaddr for AF_INET6: (address, port, flow, scope)
        sockaddr = info[4]
        ip_str = sockaddr[0]

        if not _is_public_ip(ip_str):
            # ANY private/reserved IP among the resolved set → deny (vectors 1, 2, 7).
            # Do NOT log ip_str — it leaks internal topology.
            return GuardResult(
                allowed=False, reason=_REASON_PRIVATE_IP, pinned_ip=None, hostname=host
            )

        if first_public is None:
            first_public = ip_str

    if first_public is None:
        return GuardResult(
            allowed=False, reason=_REASON_NO_PUBLIC_IP, pinned_ip=None, hostname=host
        )

    # ALL resolved IPs are public — return the first as the pinned connect address.
    return GuardResult(allowed=True, reason=None, pinned_ip=first_public, hostname=host)
