"""Unit tests for the SSRF URL guard (F-020, ADR-0023 §7).

Security-critical tests — run without network (injected resolver).
Covers all six threat vectors that the guard owns (vectors 1-7 from ADR-0023 §6).

Test design:
  - Every test uses an injected resolver (ResolverFn) so no network I/O occurs.
  - The injected resolver returns a list of addrinfo tuples mirroring socket.getaddrinfo.
  - helper _resolver(ip) builds a minimal addrinfo list for a single IP.
"""

from __future__ import annotations

import socket

from orchestration.webhooks.url_guard import (
    _is_public_ip,
    check_url,
)


def _resolver_for(ip: str):
    """Return a resolver function that always resolves to the given IP."""

    def resolver(host: str, port: int) -> list:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (ip, port))]

    return resolver


def _resolver_for_all(ips: list[str]):
    """Return a resolver function that resolves to ALL given IPs (multiple A records)."""

    def resolver(host: str, port: int) -> list:
        result = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            result.append((family, socket.SOCK_STREAM, 0, "", (ip, port)))
        return result

    return resolver


def _resolver_error(host: str, port: int) -> list:
    """Resolver that simulates a DNS failure."""
    raise OSError("DNS resolution failed (simulated)")


def _resolver_public(_host: str, port: int) -> list:
    """Resolver that always returns a safe public IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port))]


# ---------------------------------------------------------------------------
# _is_public_ip unit tests
# ---------------------------------------------------------------------------


class TestIsPublicIp:
    """Direct unit tests for the IP classification function."""

    def test_public_ipv4_allowed(self):
        assert _is_public_ip("93.184.216.34") is True  # example.com

    def test_loopback_denied(self):
        assert _is_public_ip("127.0.0.1") is False

    def test_loopback_127_x_denied(self):
        assert _is_public_ip("127.255.255.254") is False

    def test_private_10_8(self):
        assert _is_public_ip("10.0.0.1") is False

    def test_private_172_16_12(self):
        assert _is_public_ip("172.16.0.1") is False
        assert _is_public_ip("172.31.255.255") is False

    def test_private_192_168_16(self):
        assert _is_public_ip("192.168.1.1") is False

    def test_link_local_cloud_metadata(self):
        # Vector 1: cloud metadata endpoint (169.254.169.254)
        assert _is_public_ip("169.254.169.254") is False

    def test_link_local_range(self):
        assert _is_public_ip("169.254.0.1") is False

    def test_unspecified_zero(self):
        assert _is_public_ip("0.0.0.0") is False  # noqa: S104

    def test_ipv6_loopback(self):
        assert _is_public_ip("::1") is False

    def test_ipv6_ula_fc(self):
        # Vector 7: ULA fc00::/7
        assert _is_public_ip("fc00::1") is False

    def test_ipv6_ula_fd(self):
        assert _is_public_ip("fd00::1") is False

    def test_ipv4_mapped_loopback(self):
        # Vector 7: IPv4-mapped loopback (::ffff:127.0.0.1)
        assert _is_public_ip("::ffff:127.0.0.1") is False

    def test_ipv4_mapped_private(self):
        # Vector 7: IPv4-mapped private
        assert _is_public_ip("::ffff:192.168.1.1") is False

    def test_ipv4_mapped_link_local(self):
        assert _is_public_ip("::ffff:169.254.169.254") is False

    def test_ipv6_public_global(self):
        # 2001:4860:4860::8888 = Google public DNS
        assert _is_public_ip("2001:4860:4860::8888") is True

    def test_unparseable_ip_denied(self):
        assert _is_public_ip("not_an_ip") is False

    def test_broadcast_denied(self):
        # 255.255.255.255 is reserved
        assert _is_public_ip("255.255.255.255") is False


# ---------------------------------------------------------------------------
# check_url — scheme enforcement (vector 5)
# ---------------------------------------------------------------------------


class TestSchemeEnforcement:
    """Vector 5: https:// only."""

    def test_http_scheme_denied(self):
        result = check_url("http://hooks.slack.com/services/test", resolver=_resolver_public)
        assert result.allowed is False
        assert result.reason == "scheme_not_https"

    def test_ftp_scheme_denied(self):
        result = check_url("ftp://hooks.slack.com/services/test", resolver=_resolver_public)
        assert result.allowed is False
        assert result.reason == "scheme_not_https"

    def test_https_scheme_passes_scheme_check(self):
        # Slack host + public resolver → should be allowed
        result = check_url(
            "https://hooks.slack.com/services/T000/B000/secret", resolver=_resolver_public
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# check_url — port enforcement (vector 6)
# ---------------------------------------------------------------------------


class TestPortEnforcement:
    """Vector 6: only ports in the allowlist {443, 8088}."""

    def test_port_22_denied(self):
        result = check_url(
            "https://hooks.slack.com:22/services/test",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "port_not_allowed"

    def test_port_25_denied(self):
        result = check_url(
            "https://hooks.slack.com:25/services/test",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "port_not_allowed"

    def test_port_443_allowed(self):
        result = check_url(
            "https://hooks.slack.com:443/services/test",
            resolver=_resolver_public,
        )
        assert result.allowed is True

    def test_port_8088_allowed_splunk(self):
        result = check_url(
            "https://splunk.example.com:8088/services/collector",
            resolver=_resolver_for("93.184.216.34"),
            allowed_ports=frozenset({443, 8088}),
        )
        assert result.allowed is True

    def test_default_port_443_implicit(self):
        # No explicit port in URL → 443 assumed
        result = check_url(
            "https://hooks.slack.com/services/test",
            resolver=_resolver_public,
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# check_url — SSRF vectors 1, 2 (private / reserved IP blocks)
# ---------------------------------------------------------------------------


class TestSsrfPrivateRanges:
    """Vectors 1 + 2: loopback and private IP blocks blocked."""

    def test_loopback_127_blocked(self):
        result = check_url(
            "https://evil.example.com/callback",
            resolver=_resolver_for("127.0.0.1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_private_10_blocked(self):
        result = check_url(
            "https://internal.corp/api",
            resolver=_resolver_for("10.0.0.50"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_private_172_blocked(self):
        result = check_url(
            "https://db.internal/hook",
            resolver=_resolver_for("172.20.0.5"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_private_192_168_blocked(self):
        result = check_url(
            "https://router.local/hook",
            resolver=_resolver_for("192.168.0.1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"


# ---------------------------------------------------------------------------
# check_url — vector 1: link-local cloud metadata
# ---------------------------------------------------------------------------


class TestLinkLocal:
    """Vector 1: 169.254.169.254 (AWS/GCP/Azure cloud metadata)."""

    def test_cloud_metadata_link_local_blocked(self):
        result = check_url(
            "https://metadata.internal/hook",
            resolver=_resolver_for("169.254.169.254"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"


# ---------------------------------------------------------------------------
# check_url — vector 3: DNS-rebind (resolve-and-pin)
# ---------------------------------------------------------------------------


class TestDnsRebindPinned:
    """Vector 3: host resolves to a public IP when checked; we verify pinning works.

    The resolver returns the IP at check-time; the caller MUST connect to
    guard.pinned_ip (not re-resolve) to defeat a TOCTOU rebind.
    """

    def test_resolve_returns_pinned_ip(self):
        expected_ip = "93.184.216.34"
        result = check_url(
            "https://splunk.example.com/services/collector",
            resolver=_resolver_for(expected_ip),
        )
        assert result.allowed is True
        # The pinned IP MUST be the one returned by our controlled resolver.
        assert result.pinned_ip == expected_ip

    def test_rebind_private_after_public_denied(self):
        # Simulate: resolver returns one public + one private (MULTI-A-record rebind).
        # The guard must deny because ANY private IP in the set is unsafe.
        result = check_url(
            "https://rebind.example.com/hook",
            resolver=_resolver_for_all(["93.184.216.34", "169.254.169.254"]),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"


# ---------------------------------------------------------------------------
# check_url — vector 4: redirect (follow_redirects=False)
# ---------------------------------------------------------------------------


class TestNoRedirects:
    """Vector 4: redirects are never followed (enforced in guarded_http_client).

    The URL guard itself does not follow redirects — it validates the initial
    target URL. The follow_redirects=False contract is on the httpx client
    (http_client.py). This test verifies check_url does not itself make HTTP
    calls (pure resolver + IP validation).
    """

    def test_redirect_target_url_with_public_ip_allowed(self):
        # The guard allows a URL pointing to a public IP; if the server responds
        # with a 3xx, the http client (follow_redirects=False) drops it.
        result = check_url(
            "https://splunk.example.com/redirect-to-internal",
            resolver=_resolver_for("93.184.216.34"),
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# check_url — vector 7: IPv6 ULA + IPv4-mapped
# ---------------------------------------------------------------------------


class TestIpv6MappedAndUla:
    """Vector 7: IPv6 ULA and IPv4-mapped private addresses."""

    def test_ipv6_ula_fc_blocked(self):
        result = check_url(
            "https://internal.v6.example.com/hook",
            resolver=_resolver_for("fc00::1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_ipv6_ula_fd_blocked(self):
        result = check_url(
            "https://internal.v6.example.com/hook",
            resolver=_resolver_for("fd12:3456:789a::1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_ipv4_mapped_loopback_blocked(self):
        result = check_url(
            "https://mapped.example.com/hook",
            resolver=_resolver_for("::ffff:127.0.0.1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_ipv4_mapped_link_local_blocked(self):
        result = check_url(
            "https://mapped.example.com/hook",
            resolver=_resolver_for("::ffff:169.254.169.254"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"


# ---------------------------------------------------------------------------
# check_url — provider templates (§7 hardening point 4)
# ---------------------------------------------------------------------------


class TestProviderTemplates:
    """Slack and Jira provider-templated host shortcuts."""

    def test_slack_host_allowed(self):
        result = check_url(
            "https://hooks.slack.com/services/T000/B000/token",
            resolver=_resolver_public,
        )
        assert result.allowed is True
        assert result.hostname == "hooks.slack.com"

    def test_jira_atlassian_net_allowed(self):
        result = check_url(
            "https://mycompany.atlassian.net/rest/api/3/issue",
            resolver=_resolver_public,
        )
        assert result.allowed is True
        assert result.hostname == "mycompany.atlassian.net"

    def test_jira_subdomain_allowed(self):
        result = check_url(
            "https://tenant-abc.atlassian.net/rest/api/3/issue",
            resolver=_resolver_public,
        )
        assert result.allowed is True

    def test_jira_lookalike_not_allowed_via_template(self):
        # evil.atlassian.net.evil.com — should NOT match the Jira pattern.
        result = check_url(
            "https://evil.atlassian.net.evil.com/hook",
            resolver=_resolver_for("10.0.0.1"),  # private IP → strict guard → deny
        )
        assert result.allowed is False

    def test_slack_dns_fail_denied(self):
        result = check_url(
            "https://hooks.slack.com/services/test",
            resolver=_resolver_error,
        )
        assert result.allowed is False
        assert result.reason == "dns_resolve_failed"


# ---------------------------------------------------------------------------
# check_url — DNS resolution failure
# ---------------------------------------------------------------------------


class TestDnsFailure:
    """DNS resolution failure → deny conservatively."""

    def test_dns_failure_denied(self):
        result = check_url(
            "https://nxdomain.example.com/hook",
            resolver=_resolver_error,
        )
        assert result.allowed is False
        assert result.reason == "dns_resolve_failed"

    def test_empty_addrinfo_denied(self):
        result = check_url(
            "https://empty.example.com/hook",
            resolver=lambda h, p: [],
        )
        assert result.allowed is False
        assert result.reason == "no_public_ip_resolved"


# ---------------------------------------------------------------------------
# check_url — empty / malformed URL
# ---------------------------------------------------------------------------


class TestMalformedUrls:
    def test_empty_url_denied(self):
        result = check_url("", resolver=_resolver_public)
        assert result.allowed is False

    def test_no_host_denied(self):
        result = check_url("https:///path", resolver=_resolver_public)
        assert result.allowed is False
        assert result.reason == "host_empty"


# ---------------------------------------------------------------------------
# GuardResult fields
# ---------------------------------------------------------------------------


class TestGuardResultFields:
    def test_allowed_result_has_pinned_ip(self):
        result = check_url(
            "https://splunk.example.com/services/collector",
            resolver=_resolver_for("93.184.216.34"),
        )
        assert result.allowed is True
        assert result.pinned_ip == "93.184.216.34"
        assert result.reason is None
        assert result.hostname == "splunk.example.com"

    def test_denied_result_has_no_pinned_ip(self):
        result = check_url(
            "https://private.example.com/hook",
            resolver=_resolver_for("10.1.2.3"),
        )
        assert result.allowed is False
        assert result.pinned_ip is None
        assert result.reason is not None
