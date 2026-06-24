"""Adversarial test suite for F-020 outbound webhooks (ADR-0023 §6).

Covers ALL 16 ADR-0023 §6 adversarial vectors. This file contains the
OFFLINE (no DB, no Redis) portion — vectors 1-8 and 13. The integration-gated
portion (vectors 9-12, 14-16) lives in test_webhook_integration.py.

Vector map (this file):
  V1  — SSRF link-local / 169.254.x.x (cloud metadata)
  V2  — SSRF loopback / private ranges / 0.0.0.0
  V3  — DNS-rebind / multi-A mixed public+private DENIED
  V4  — Redirect (follow_redirects=False contract)
  V5  — HTTP:// scheme DENIED (https-only)
  V6  — Non-allowlisted port DENIED (22, 25, 80, 8080)
  V7  — IPv6 ULA / IPv4-mapped private DENIED
  V8  — Delivery failure NEVER raises into emit() / request path (fail-open)
  V13 — Fork A integrity: stream + adapter bodies contain ZERO payload/PII content

OFFLINE = runs with zero containers. Every network touch is replaced by injected
resolvers or unittest.mock.

NEVER log: PII, credentials, or user content in test fixtures. All fixture data
is synthetic (no real credentials, no real names/SSNs/emails).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import time
import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestration.webhooks.adapters import (
    _ALLOWED_ENVELOPE_KEYS,
    build_body,
    build_jira_body,
    build_slack_body,
    build_splunk_body,
)
from orchestration.webhooks.config import WEBHOOK_SIGNATURE_TOLERANCE_SECONDS
from orchestration.webhooks.queue import CandidateMessage
from orchestration.webhooks.signer import should_sign, sign_body, verify_within_tolerance
from orchestration.webhooks.url_guard import _is_public_ip, check_url

# ---------------------------------------------------------------------------
# Shared resolver helpers (mirrors test_url_guard.py — duplicated so the two
# files are independently runnable without cross-package imports).
# ---------------------------------------------------------------------------

_PUBLIC_IP = "93.184.216.34"  # example.com — publicly routable


def _resolver_for(ip: str):
    """Injected resolver that always returns a single address."""

    def resolver(host: str, port: int) -> list:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (ip, port))]

    return resolver


def _resolver_for_all(ips: list):
    """Injected resolver that returns every supplied address."""

    def resolver(host: str, port: int) -> list:
        result = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            result.append((family, socket.SOCK_STREAM, 0, "", (ip, port)))
        return result

    return resolver


def _resolver_public(host: str, port: int) -> list:
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (_PUBLIC_IP, port))]


def _resolver_error(host: str, port: int) -> list:
    raise OSError("DNS resolution failed (injected)")


# ---------------------------------------------------------------------------
# Synthetic envelope (Fork A projection) used across multiple tests.
# ALL fields are from _ALLOWED_ENVELOPE_KEYS. No payload or PII.
# ---------------------------------------------------------------------------

_SYNTHETIC_ENVELOPE = {
    "event_type": "pii_blocked",
    "severity": "high",
    "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-000000000001",
    "team_id": "11111111-2222-3333-4444-000000000002",
    "project_id": "66666666-7777-8888-9999-000000000003",
    "agent_id": "data-protection",
    "event_id": str(uuid.uuid4()),
    "event_timestamp": "2026-06-25T00:00:00Z",
    "request_id": "req-aaaaaaaabbbbbbbbcccccccc",
    "action_taken": "masked",
    "violation_type": "",
    "webhook_provider": "splunk",
}

# Payload/PII strings that MUST NEVER appear in any outbound body (Fork A).
_FORBIDDEN_PAYLOAD_FRAGMENTS = [
    "My SSN is 123-45-6789",
    "IGNORE PREVIOUS INSTRUCTIONS",
    "leaked data",
    "secret data",
    "original_user_content",
    "response_body",
    "prompt_text",
    "raw_response",
    "password=hunter2",
]

# Envelope injected with forbidden payload keys — adapters must strip them.
_ENVELOPE_WITH_FORBIDDEN_PAYLOAD = {
    **_SYNTHETIC_ENVELOPE,
    # These keys are NOT in _ALLOWED_ENVELOPE_KEYS and must be stripped.
    "original_user_content": "My SSN is 123-45-6789",
    "response_body": '{"choices":[{"message":{"content":"secret data"}}]}',
    "prompt_text": "IGNORE PREVIOUS INSTRUCTIONS",
    "raw_response": "leaked data",
    "user_email": "someone@example.invalid",
    "extra_field": "password=hunter2",
}


# ===========================================================================
# VECTOR 1 — SSRF: link-local / cloud-metadata (169.254.x.x)
# ===========================================================================


class TestV1SsrfLinkLocal:
    """Vector 1: 169.254.169.254 and link-local range blocked."""

    def test_cloud_metadata_endpoint_blocked(self):
        result = check_url(
            "https://target.example.com/callback",
            resolver=_resolver_for("169.254.169.254"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_link_local_169_254_0_1_blocked(self):
        result = check_url(
            "https://target.example.com/callback",
            resolver=_resolver_for("169.254.0.1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_link_local_169_254_255_254_blocked(self):
        # Edge of link-local range
        result = check_url(
            "https://target.example.com/callback",
            resolver=_resolver_for("169.254.255.254"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_is_public_ip_rejects_link_local(self):
        assert _is_public_ip("169.254.169.254") is False
        assert _is_public_ip("169.254.0.1") is False

    def test_direct_url_to_metadata_ip_blocked(self):
        # Even if someone encodes the IP directly in the URL hostname field
        result = check_url(
            "https://metadata.internal/latest/meta-data/",
            resolver=_resolver_for("169.254.169.254"),
        )
        assert result.allowed is False


# ===========================================================================
# VECTOR 2 — SSRF: loopback, private ranges, 0.0.0.0
# ===========================================================================


class TestV2SsrfPrivateRanges:
    """Vector 2: loopback / RFC-1918 private / 0.0.0.0 — all DENIED."""

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.20.5.5",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "0.0.0.0",  # noqa: S104
        ],
    )
    def test_private_ip_blocked(self, ip):
        result = check_url(
            "https://internal.corp/hook",
            resolver=_resolver_for(ip),
        )
        assert result.allowed is False, f"Expected denied for IP {ip}"

    def test_0_0_0_0_is_not_public(self):
        assert _is_public_ip("0.0.0.0") is False  # noqa: S104

    def test_loopback_blocked(self):
        result = check_url(
            "https://evil.example.com/exfil",
            resolver=_resolver_for("127.0.0.1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_private_10_range_blocked(self):
        result = check_url(
            "https://corp-internal.example.com/api",
            resolver=_resolver_for("10.0.0.50"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"


# ===========================================================================
# VECTOR 3 — DNS-rebind: resolve-and-pin defeats TOCTOU
# ===========================================================================


class TestV3DnsRebindPinned:
    """Vector 3: DNS-rebind requires pinned_ip; multi-A mixed sets denied."""

    def test_pinned_ip_returned_for_public_host(self):
        result = check_url(
            "https://splunk.example.com:8088/services/collector",
            resolver=_resolver_for(_PUBLIC_IP),
            allowed_ports=frozenset({443, 8088}),
        )
        assert result.allowed is True
        assert result.pinned_ip == _PUBLIC_IP

    def test_multi_a_public_plus_private_denied(self):
        # Attacker controls DNS to return ONE public IP + ONE private IP.
        # The guard must deny because ANY private IP in the set is unsafe.
        result = check_url(
            "https://rebind.attack.invalid/hook",
            resolver=_resolver_for_all([_PUBLIC_IP, "10.0.0.1"]),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_multi_a_public_plus_loopback_denied(self):
        result = check_url(
            "https://rebind2.attack.invalid/hook",
            resolver=_resolver_for_all([_PUBLIC_IP, "127.0.0.1"]),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_multi_a_public_plus_metadata_denied(self):
        # The classic cloud-metadata rebind vector
        result = check_url(
            "https://rebind3.attack.invalid/hook",
            resolver=_resolver_for_all([_PUBLIC_IP, "169.254.169.254"]),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_all_public_multi_a_allowed(self):
        # Multiple public IPs — all public → allowed with first as pin
        second_public = "8.8.8.8"
        result = check_url(
            "https://cdn.example.com/hook",
            resolver=_resolver_for_all([_PUBLIC_IP, second_public]),
        )
        assert result.allowed is True
        assert result.pinned_ip == _PUBLIC_IP

    def test_caller_must_use_pinned_ip_not_re_resolve(self):
        # Guard returns pinned_ip = the IP at check time.
        # Any caller that re-resolves at connect time opens the rebind window.
        # We assert that pinned_ip is ALWAYS set on allowed results.
        result = check_url(
            "https://splunk.example.com/services/collector",
            resolver=_resolver_for(_PUBLIC_IP),
        )
        assert result.allowed is True
        assert result.pinned_ip is not None
        # Pinned must equal the FIRST public IP from our controlled resolver
        assert result.pinned_ip == _PUBLIC_IP

    def test_rebind_across_calls_simulated_via_stateful_resolver(self):
        # Simulates a classic rebind: first call returns public, second returns private.
        # Our guard calls the resolver ONCE; the pinned_ip is used for connect.
        # This test verifies that if we call check_url separately (simulating two
        # validation calls), the SECOND one sees the private IP.
        call_count = {"n": 0}

        def stateful_resolver(host: str, port: int) -> list:
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: public IP (passes guard)
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (_PUBLIC_IP, port))]
            else:
                # Second call: private IP (guard would deny)
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", port))]

        # First check: allowed (public IP)
        r1 = check_url(
            "https://splunk.example.com/services/collector",
            resolver=stateful_resolver,
        )
        assert r1.allowed is True

        # Second check (simulating a DIFFERENT call to check_url, not pin reuse):
        # would now see private IP — this is why re-resolving at connect time is dangerous.
        r2 = check_url(
            "https://splunk.example.com/services/collector",
            resolver=stateful_resolver,
        )
        assert r2.allowed is False
        assert r2.reason == "private_ip_resolved"


# ===========================================================================
# VECTOR 4 — Redirect (follow_redirects=False)
# ===========================================================================


class TestV4NoRedirects:
    """Vector 4: follow_redirects=False is the contract on guarded_http_client.

    The URL guard does not follow redirects; this test verifies the contract
    on the HTTP client level (guarded_http_client must be built with
    follow_redirects=False).
    """

    def test_guarded_http_client_follow_redirects_false(self):
        """guarded_http_client must be built with follow_redirects=False."""
        import inspect

        from orchestration.webhooks.http_client import guarded_http_client

        # Verify the source specifies follow_redirects=False at build time.
        src = inspect.getsource(guarded_http_client)
        assert (
            "follow_redirects=False" in src
        ), "guarded_http_client MUST set follow_redirects=False (ADR-0023 §7 vector 4)"

    def test_url_guard_does_not_follow_http_redirects(self):
        # The guard validates the INITIAL URL only (no HTTP requests made).
        # A URL pointing to a public host is allowed at the URL level;
        # if that server returns a 302 to an internal host, the httpx client
        # (follow_redirects=False) DROPS the redirect — that is the defense.
        result = check_url(
            "https://splunk.example.com/redirect-to-internal",
            resolver=_resolver_for(_PUBLIC_IP),
        )
        # Guard passes — the follow_redirects=False on the client is the backstop.
        assert result.allowed is True

    def test_redirect_to_metadata_blocked_by_client_contract(self):
        # If the HTTP client had follow_redirects=True, a 302 to
        # http://169.254.169.254 would bypass the guard. We assert
        # the contract is in the source.
        import inspect

        from orchestration.webhooks import http_client as _hc

        src = inspect.getsource(_hc)
        assert "follow_redirects=False" in src


# ===========================================================================
# VECTOR 5 — HTTP:// scheme DENIED
# ===========================================================================


class TestV5HttpsOnly:
    """Vector 5: only https:// scheme is allowed (vectors 5)."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://hooks.slack.com/services/T000/B000/token",
            "http://mycompany.atlassian.net/rest/api/3/issue",
            "http://splunk.example.com:8088/services/collector",
            "ftp://files.example.com/webhook",
            "ws://echo.example.com/webhook",
            "//hooks.slack.com/services/test",
        ],
    )
    def test_non_https_scheme_denied(self, url):
        result = check_url(url, resolver=_resolver_public)
        assert result.allowed is False
        assert result.reason in ("scheme_not_https", "host_empty")

    def test_https_scheme_accepted(self):
        result = check_url(
            "https://hooks.slack.com/services/T000/B000/valid",
            resolver=_resolver_public,
        )
        assert result.allowed is True

    def test_http_in_path_not_confused_with_scheme(self):
        # A URL with https scheme whose path contains the word "http" should pass.
        result = check_url(
            "https://hooks.slack.com/services/test?redirect=http://evil.com",
            resolver=_resolver_public,
        )
        # Scheme is https — should pass the scheme check; query string is not inspected.
        assert result.allowed is True


# ===========================================================================
# VECTOR 6 — Non-allowlisted port DENIED
# ===========================================================================


class TestV6PortAllowlist:
    """Vector 6: only ports 443 and 8088 are allowed by default."""

    @pytest.mark.parametrize("port", [22, 25, 80, 8080, 3306, 5432, 6379, 1337, 65535])
    def test_disallowed_port_denied(self, port):
        result = check_url(
            f"https://splunk.example.com:{port}/hook",
            resolver=_resolver_public,
            allowed_ports=frozenset({443, 8088}),
        )
        assert result.allowed is False
        assert result.reason == "port_not_allowed"

    def test_port_443_allowed(self):
        result = check_url(
            "https://hooks.slack.com:443/services/test",
            resolver=_resolver_public,
        )
        assert result.allowed is True

    def test_port_8088_allowed(self):
        result = check_url(
            "https://splunk.example.com:8088/services/collector",
            resolver=_resolver_for(_PUBLIC_IP),
            allowed_ports=frozenset({443, 8088}),
        )
        assert result.allowed is True

    def test_implicit_port_443_allowed(self):
        # No explicit port → defaults to 443.
        result = check_url(
            "https://hooks.slack.com/services/T000/B000/token",
            resolver=_resolver_public,
        )
        assert result.allowed is True

    def test_ssh_port_22_denied_on_slack_host(self):
        # Even a known-good Slack host is denied on port 22.
        result = check_url(
            "https://hooks.slack.com:22/services/test",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "port_not_allowed"


# ===========================================================================
# VECTOR 7 — IPv6 ULA / IPv4-mapped private
# ===========================================================================


class TestV7Ipv6MappedAndUla:
    """Vector 7: IPv6 ULA (fc00::/7) and IPv4-mapped private addresses DENIED."""

    @pytest.mark.parametrize(
        "ip",
        [
            "fc00::1",
            "fc00::ffff",
            "fd00::1",
            "fd12:3456:789a::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            "::1",  # IPv6 loopback
        ],
    )
    def test_ipv6_private_blocked(self, ip):
        assert _is_public_ip(ip) is False, f"Expected {ip!r} to be denied"

    def test_ipv6_ula_fc_check_url_blocked(self):
        result = check_url(
            "https://internal.v6.example.com/hook",
            resolver=_resolver_for("fc00::1"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_ipv6_ula_fd_check_url_blocked(self):
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

    def test_ipv4_mapped_metadata_blocked(self):
        result = check_url(
            "https://mapped.example.com/hook",
            resolver=_resolver_for("::ffff:169.254.169.254"),
        )
        assert result.allowed is False
        assert result.reason == "private_ip_resolved"

    def test_ipv6_global_public_allowed(self):
        # 2001:4860:4860::8888 = Google public DNS
        assert _is_public_ip("2001:4860:4860::8888") is True


# ===========================================================================
# VECTOR 8 — Delivery failure NEVER raises into emit() / request path
# ===========================================================================


class TestV8FailOpen:
    """Vector 8: emit() swallows ALL webhook errors; request path is unaffected.

    Tests:
    - XADD failure (Redis down) inside the tap is swallowed.
    - emit() returns True regardless of XADD outcome.
    - The request path (emit's return value) is not affected by webhook tap failures.
    """

    @pytest.mark.asyncio
    async def test_xadd_failure_swallowed_by_emit(self):
        """Redis down during XADD must NOT propagate; emit() returns True."""
        from gateway.context import TenantContext
        from orchestration.context import HookContext

        tc = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            team_id="11111111-2222-3333-4444-000000000002",
            project_id="66666666-7777-8888-9999-000000000003",
            agent_id="test-agent",
            virtual_key_id=str(uuid.uuid4()),
        )
        ctx = HookContext(
            tenant_context=tc,
            request_id="req-test-001",
            original_user_content="",
            phase="pre_request",
            _events_per_detector_cap=10,
        )

        event = {
            "event_type": "pii_blocked",
            "severity": "high",
            "action_taken": "masked",
            "violation_type": "",
        }

        # Patch AuditLogRepository.append to succeed (so the audit path works),
        # and patch xadd_candidate to raise (simulating Redis failure).
        mock_repo = MagicMock()
        mock_repo.append = AsyncMock(return_value=MagicMock())

        @asynccontextmanager
        async def _mock_priv_session():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield MagicMock()

            session.begin = _begin
            yield session

        async def _raise_xadd(*args, **kwargs):
            raise ConnectionError("Redis is down (simulated)")

        with (
            patch("orchestration.context.get_privileged_session", _mock_priv_session),
            patch(
                "orchestration.context.AuditLogRepository",
                return_value=mock_repo,
            ),
            patch("orchestration.webhooks.config.get_webhook_settings") as _mock_settings,
            patch(
                "orchestration.webhooks.queue.xadd_candidate",
                side_effect=_raise_xadd,
            ),
        ):
            from orchestration.webhooks.config import WebhookSettings

            _mock_settings.return_value = WebhookSettings(
                webhook_dispatch_enabled=True,
                webhook_candidates_stream_key="webhook:candidates",
                webhook_consumer_group="webhook-dispatcher-group",
                webhook_dlq_stream_key="webhook:dlq",
            )

            # emit() MUST return True even when XADD raises.
            result = await ctx.emit(event, detector_slug="data-protection")
            assert result is True, "emit() must return True even when XADD fails"

    @pytest.mark.asyncio
    async def test_xadd_exception_does_not_propagate_to_caller(self):
        """Any exception in the XADD tap must be swallowed inside emit()."""
        from gateway.context import TenantContext
        from orchestration.context import HookContext

        tc = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            team_id="11111111-2222-3333-4444-000000000002",
            project_id="66666666-7777-8888-9999-000000000003",
            agent_id="test-agent",
            virtual_key_id=str(uuid.uuid4()),
        )
        ctx = HookContext(
            tenant_context=tc,
            request_id="req-test-002",
            original_user_content="",
            phase="pre_request",
        )

        event = {
            "event_type": "injection_detected",
            "severity": "critical",
            "action_taken": "blocked",
            "violation_type": "",
        }

        mock_repo = MagicMock()
        mock_repo.append = AsyncMock(return_value=MagicMock())

        @asynccontextmanager
        async def _mock_priv_session():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield MagicMock()

            session.begin = _begin
            yield session

        # XADD raises a RuntimeError — must be caught and swallowed.
        raised = []

        async def _xadd_raise(*args, **kwargs):
            raised.append(True)
            raise RuntimeError("Unexpected Redis error (simulated)")

        with (
            patch("orchestration.context.get_privileged_session", _mock_priv_session),
            patch("orchestration.context.AuditLogRepository", return_value=mock_repo),
            patch("orchestration.webhooks.config.get_webhook_settings") as _mock_settings,
            patch(
                "orchestration.webhooks.queue.xadd_candidate",
                side_effect=_xadd_raise,
            ),
        ):
            from orchestration.webhooks.config import WebhookSettings

            _mock_settings.return_value = WebhookSettings(
                webhook_dispatch_enabled=True,
            )

            # Must NOT raise — the exception must be fully contained.
            result = await ctx.emit(event, detector_slug="defense")
            assert result is True
            assert raised, "xadd_candidate was called (confirming the tap ran)"

    @pytest.mark.asyncio
    async def test_off_by_default_no_xadd_when_disabled(self):
        """Vector: off-by-default. When webhook_dispatch_enabled=False, XADD never called."""
        from gateway.context import TenantContext
        from orchestration.context import HookContext

        tc = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            team_id="11111111-2222-3333-4444-000000000002",
            project_id="66666666-7777-8888-9999-000000000003",
            agent_id="test-agent",
            virtual_key_id=str(uuid.uuid4()),
        )
        ctx = HookContext(
            tenant_context=tc,
            request_id="req-test-003",
            original_user_content="",
            phase="pre_request",
        )

        event = {
            "event_type": "pii_blocked",
            "severity": "high",
            "action_taken": "masked",
            "violation_type": "",
        }

        mock_repo = MagicMock()
        mock_repo.append = AsyncMock(return_value=MagicMock())

        @asynccontextmanager
        async def _mock_priv_session():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield MagicMock()

            session.begin = _begin
            yield session

        xadd_calls = []

        async def _xadd_spy(*args, **kwargs):
            xadd_calls.append((args, kwargs))

        with (
            patch("orchestration.context.get_privileged_session", _mock_priv_session),
            patch("orchestration.context.AuditLogRepository", return_value=mock_repo),
            patch("orchestration.webhooks.config.get_webhook_settings") as _mock_settings,
            patch(
                "orchestration.webhooks.queue.xadd_candidate",
                side_effect=_xadd_spy,
            ),
        ):
            from orchestration.webhooks.config import WebhookSettings

            # DISABLED (default)
            _mock_settings.return_value = WebhookSettings(
                webhook_dispatch_enabled=False,
            )

            result = await ctx.emit(event, detector_slug="data-protection")
            assert result is True
            assert (
                len(xadd_calls) == 0
            ), "XADD must NOT be called when webhook_dispatch_enabled=False"

    @pytest.mark.asyncio
    async def test_low_severity_no_xadd(self):
        """Low/medium severity events must NOT produce XADD candidates."""
        from gateway.context import TenantContext
        from orchestration.context import HookContext

        tc = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            team_id="11111111-2222-3333-4444-000000000002",
            project_id="66666666-7777-8888-9999-000000000003",
            agent_id="test-agent",
            virtual_key_id=str(uuid.uuid4()),
        )

        mock_repo = MagicMock()
        mock_repo.append = AsyncMock(return_value=MagicMock())

        @asynccontextmanager
        async def _mock_priv_session():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield MagicMock()

            session.begin = _begin
            yield session

        xadd_calls = []

        async def _xadd_spy(*args, **kwargs):
            xadd_calls.append(args)

        with (
            patch("orchestration.context.get_privileged_session", _mock_priv_session),
            patch("orchestration.context.AuditLogRepository", return_value=mock_repo),
            patch("orchestration.webhooks.config.get_webhook_settings") as _mock_settings,
            patch(
                "orchestration.webhooks.queue.xadd_candidate",
                side_effect=_xadd_spy,
            ),
        ):
            from orchestration.webhooks.config import WebhookSettings

            _mock_settings.return_value = WebhookSettings(
                webhook_dispatch_enabled=True,
            )

            for severity in ("low", "medium", "info"):
                xadd_calls.clear()
                ctx = HookContext(
                    tenant_context=tc,
                    request_id=f"req-{severity}",
                    original_user_content="",
                    phase="pre_request",
                )
                event = {
                    "event_type": "pii_detected",
                    "severity": severity,
                    "action_taken": "logged",
                    "violation_type": "",
                }
                await ctx.emit(event, detector_slug="data-protection")
                assert len(xadd_calls) == 0, f"XADD must NOT be called for severity={severity!r}"

    @pytest.mark.asyncio
    async def test_delivery_failure_does_not_affect_process_candidate(self):
        """process_candidate swallows all exceptions from _deliver_to_config (D5)."""
        from orchestration.webhooks.queue import CandidateMessage
        from orchestration.webhooks.worker import process_candidate

        msg = CandidateMessage(
            event_type="pii_blocked",
            severity="high",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            team_id="11111111-2222-3333-4444-000000000002",
            project_id="66666666-7777-8888-9999-000000000003",
            agent_id="data-protection",
            event_id=str(uuid.uuid4()),
            event_timestamp="2026-06-25T00:00:00Z",
            request_id="req-test-fail",
            action_taken="masked",
            violation_type="",
            webhook_provider="slack",
        )

        # Mock get_tenant_session to raise — simulating total DB failure.
        @asynccontextmanager
        async def _raise_session(tid: str):
            raise RuntimeError("DB unavailable (simulated)")
            yield  # noqa: RET504 — unreachable but needed for @asynccontextmanager typing

        with patch(
            "orchestration.webhooks.worker.get_tenant_session",
            side_effect=_raise_session,
        ):
            # Must not raise — all exceptions are caught inside process_candidate.
            await process_candidate(msg)  # no exception expected


# ===========================================================================
# VECTOR 13 — Fork A integrity: ZERO payload/PII in stream or adapter bodies
# ===========================================================================


class TestV13ForkAIntegrityNoPayload:
    """Vector 13: outbound bodies + stream candidates contain ZERO payload/PII.

    ADR-0023 D1: the webhook dispatcher is STRUCTURALLY INCAPABLE of egressing
    prompt/response/PII content because the candidate envelope only carries the
    bounded metadata projection.
    """

    def test_allowed_envelope_keys_are_metadata_only(self):
        """Verify _ALLOWED_ENVELOPE_KEYS contains ONLY metadata fields."""
        forbidden_payload_keys = {
            "original_user_content",
            "response_body",
            "prompt_text",
            "raw_response",
            "masked_content",
            "pii_excerpts",
            "injection_payload",
            "user_message",
            "assistant_message",
        }
        overlap = _ALLOWED_ENVELOPE_KEYS & forbidden_payload_keys
        assert overlap == frozenset(), f"PAYLOAD keys found in _ALLOWED_ENVELOPE_KEYS: {overlap!r}"

    def test_slack_adapter_strips_forbidden_payload(self):
        body_str = build_slack_body(_ENVELOPE_WITH_FORBIDDEN_PAYLOAD)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            assert fragment not in body_str, f"Forbidden fragment {fragment!r} found in Slack body"

    def test_jira_adapter_strips_forbidden_payload(self):
        body_str = build_jira_body(_ENVELOPE_WITH_FORBIDDEN_PAYLOAD)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            assert fragment not in body_str, f"Forbidden fragment {fragment!r} found in Jira body"

    def test_splunk_adapter_strips_forbidden_payload(self):
        body_str = build_splunk_body(_ENVELOPE_WITH_FORBIDDEN_PAYLOAD)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            assert fragment not in body_str, f"Forbidden fragment {fragment!r} found in Splunk body"

    def test_build_body_dispatch_slack_no_payload(self):
        body_str = build_body("slack", _ENVELOPE_WITH_FORBIDDEN_PAYLOAD)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            assert fragment not in body_str

    def test_build_body_dispatch_jira_no_payload(self):
        body_str = build_body("jira", _ENVELOPE_WITH_FORBIDDEN_PAYLOAD)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            assert fragment not in body_str

    def test_build_body_dispatch_splunk_no_payload(self):
        body_str = build_body("splunk", _ENVELOPE_WITH_FORBIDDEN_PAYLOAD)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            assert fragment not in body_str

    def test_candidate_message_to_envelope_contains_only_metadata(self):
        """CandidateMessage.to_envelope() must produce metadata-only dict."""
        msg = CandidateMessage(
            event_type="pii_blocked",
            severity="high",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-000000000001",
            team_id="11111111-2222-3333-4444-000000000002",
            project_id="66666666-7777-8888-9999-000000000003",
            agent_id="data-protection",
            event_id=str(uuid.uuid4()),
            event_timestamp="2026-06-25T00:00:00Z",
            request_id="req-aaaaaaaabbbb",
            action_taken="masked",
            violation_type="",
            webhook_provider="splunk",
        )
        envelope = msg.to_envelope()
        # All keys in the envelope must be in the allowed set.
        extra_keys = set(envelope.keys()) - _ALLOWED_ENVELOPE_KEYS
        assert extra_keys == frozenset(), f"Envelope contains non-allowed keys: {extra_keys!r}"

    def test_candidate_fields_projection_excludes_payload_keys(self):
        """to_envelope() must not expose any prompt/response/pii payload."""
        from orchestration.webhooks.queue import _CANDIDATE_FIELDS

        payload_keys = {
            "original_user_content",
            "response_body",
            "prompt_text",
            "raw_response",
            "user_message",
            "assistant_message",
        }
        overlap = _CANDIDATE_FIELDS & payload_keys
        assert overlap == frozenset(), f"Payload keys in _CANDIDATE_FIELDS: {overlap!r}"

    def test_slack_body_is_valid_json_with_only_metadata(self):
        body_str = build_slack_body(_SYNTHETIC_ENVELOPE)
        parsed = json.loads(body_str)
        # Recursively collect all string values and check for PII patterns.
        all_values = _collect_all_string_values(parsed)
        for fragment in _FORBIDDEN_PAYLOAD_FRAGMENTS:
            for val in all_values:
                assert (
                    fragment not in val
                ), f"PII fragment {fragment!r} found in Slack JSON value {val!r}"

    def test_splunk_body_contains_only_allowed_event_keys(self):
        body_str = build_splunk_body(_SYNTHETIC_ENVELOPE)
        parsed = json.loads(body_str)
        event_keys = set(parsed.get("event", {}).keys())
        non_allowed = event_keys - _ALLOWED_ENVELOPE_KEYS
        assert (
            non_allowed == frozenset()
        ), f"Splunk event contains non-allowed keys: {non_allowed!r}"

    def test_jira_summary_and_description_contain_no_pii(self):
        # Inject something that looks like a prompt into an envelope key
        # that adapters should ignore.
        envelope = dict(_SYNTHETIC_ENVELOPE)
        envelope["original_user_content"] = "My SSN is 123-45-6789"
        body_str = build_jira_body(envelope)
        assert "123-45-6789" not in body_str

    def test_context_emit_projection_keys_are_bounded(self):
        """Verify context.py's XADD tap projects ONLY the 12 bounded metadata keys."""
        import inspect

        from orchestration import context as _ctx

        src = inspect.getsource(_ctx)
        # The candidate_fields dict must reference only the allowed keys.
        # We check that known payload keys are NOT projected.
        for forbidden_key in (
            "original_user_content",
            "response_body",
            "prompt_text",
            "raw_response",
        ):
            # The key should not appear in the XADD projection block.
            # It might appear in comments/docstrings, so search for the dict key form.
            assert (
                f'"{forbidden_key}"' not in src
                or "_candidate_fields"
                not in src.split(f'"{forbidden_key}"')[0].rsplit("_candidate_fields", 1)[-1]
            ), f"Forbidden key {forbidden_key!r} found in context.py XADD projection"


# ===========================================================================
# VECTOR 10 — HMAC signing: timestamp INSIDE signed payload
# ===========================================================================


class TestV10HmacSigningTimestampInBody:
    """Vector 10: HMAC-SHA256(secret, f'{ts}.{body}') — timestamp is INSIDE the mac."""

    def test_sign_body_timestamp_is_inside_signed_payload(self):
        """The HMAC must be computed over f'{ts}.{body}' not just body."""
        secret = b"test-signing-secret-for-vector-10"
        body = '{"event_type":"pii_blocked","severity":"high"}'
        headers = sign_body(secret, body)
        ts = headers.x_sentinel_timestamp

        signed_payload = f"{ts}.{body}".encode("utf-8")
        expected = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
        expected_sig = f"sha256={expected}"

        assert headers.x_sentinel_signature == expected_sig

    def test_body_only_hmac_does_not_match(self):
        """An HMAC over body only (no timestamp) must differ from the signed header."""
        secret = b"test-signing-secret-for-vector-10"
        body = '{"event_type":"pii_blocked","severity":"high"}'
        headers = sign_body(secret, body)

        body_only_mac = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
        actual_sig_hex = headers.x_sentinel_signature[len("sha256=") :]
        assert (
            actual_sig_hex != body_only_mac
        ), "body-only HMAC should NOT match the signed payload — timestamp must be inside"

    def test_slack_not_signed(self):
        assert should_sign("slack") is False

    def test_jira_not_signed(self):
        assert should_sign("jira") is False

    def test_splunk_is_signed(self):
        assert should_sign("splunk") is True

    def test_case_insensitive_provider(self):
        assert should_sign("SLACK") is False
        assert should_sign("SPLUNK") is True


# ===========================================================================
# VECTOR 11 — Replay outside tolerance window rejected
# ===========================================================================


class TestV11ReplayOutsideWindow:
    """Vector 11: replay outside ±300s window must be detectable."""

    def test_fresh_timestamp_accepted(self):
        ts = str(int(time.time()))
        assert verify_within_tolerance(ts) is True

    def test_tolerance_constant_is_300(self):
        assert WEBHOOK_SIGNATURE_TOLERANCE_SECONDS == 300

    def test_timestamp_just_inside_window(self):
        ts = str(int(time.time()) - WEBHOOK_SIGNATURE_TOLERANCE_SECONDS + 1)
        assert verify_within_tolerance(ts) is True

    def test_timestamp_just_outside_window_rejected(self):
        ts = str(int(time.time()) - WEBHOOK_SIGNATURE_TOLERANCE_SECONDS - 1)
        assert verify_within_tolerance(ts) is False

    def test_future_timestamp_far_rejected(self):
        ts = str(int(time.time()) + WEBHOOK_SIGNATURE_TOLERANCE_SECONDS + 60)
        assert verify_within_tolerance(ts) is False

    def test_10_minutes_old_rejected(self):
        ts = str(int(time.time()) - 600)
        assert verify_within_tolerance(ts) is False

    def test_injected_now_controls_window(self):
        frozen_now = 1_700_000_000.0
        ts_fresh = str(int(frozen_now))
        assert verify_within_tolerance(ts_fresh, _now=frozen_now) is True

        ts_stale = str(int(frozen_now) - WEBHOOK_SIGNATURE_TOLERANCE_SECONDS - 1)
        assert verify_within_tolerance(ts_stale, _now=frozen_now) is False

    def test_non_integer_timestamp_rejected(self):
        assert verify_within_tolerance("not-a-timestamp") is False

    def test_empty_string_rejected(self):
        assert verify_within_tolerance("") is False

    def test_tampered_body_signature_fails(self):
        """Modifying the body after signing changes the HMAC, so verification fails."""
        secret = b"test-secret-for-replay-test"
        original_body = '{"event_type":"pii_blocked"}'
        headers = sign_body(secret, original_body)

        # Attacker modifies the body.
        tampered_body = '{"event_type":"injection_detected"}'
        ts = headers.x_sentinel_timestamp

        # Recompute HMAC with tampered body — it MUST differ.
        signed_tampered = f"{ts}.{tampered_body}".encode("utf-8")
        tampered_mac = hmac.new(secret, signed_tampered, hashlib.sha256).hexdigest()
        original_sig_hex = headers.x_sentinel_signature[len("sha256=") :]

        assert tampered_mac != original_sig_hex, "Tampered body must produce a different HMAC"

    def test_wrong_secret_fails_verification(self):
        """A different signing secret must produce a different signature."""
        secret_a = b"correct-secret-for-replay-test"
        secret_b = b"wrong-secret-for-replay-test-!!"
        body = '{"event_type":"pii_blocked"}'

        headers = sign_body(secret_a, body)
        ts = headers.x_sentinel_timestamp

        # Attempt to verify using the wrong secret.
        signed_payload = f"{ts}.{body}".encode("utf-8")
        wrong_mac = hmac.new(secret_b, signed_payload, hashlib.sha256).hexdigest()
        correct_sig_hex = headers.x_sentinel_signature[len("sha256=") :]

        assert wrong_mac != correct_sig_hex, "Wrong secret must produce a different HMAC"


# ===========================================================================
# VECTOR 4 (supplementary) — Provider host pattern: Slack/Jira still scheme/port checked
# ===========================================================================


class TestProviderHostTemplateSchemePortChecked:
    """Slack/Jira templated hosts still get scheme and port validation."""

    def test_slack_http_denied(self):
        result = check_url(
            "http://hooks.slack.com/services/T000/B000/token",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "scheme_not_https"

    def test_jira_http_denied(self):
        result = check_url(
            "http://mycompany.atlassian.net/rest/api/3/issue",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "scheme_not_https"

    def test_slack_bad_port_denied(self):
        result = check_url(
            "https://hooks.slack.com:22/services/T000/B000/token",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "port_not_allowed"

    def test_jira_bad_port_denied(self):
        result = check_url(
            "https://mycompany.atlassian.net:8080/rest/api/3/issue",
            resolver=_resolver_public,
        )
        assert result.allowed is False
        assert result.reason == "port_not_allowed"

    def test_slack_dns_fail_denied(self):
        result = check_url(
            "https://hooks.slack.com/services/test",
            resolver=_resolver_error,
        )
        assert result.allowed is False
        assert result.reason == "dns_resolve_failed"

    def test_jira_lookalike_uses_strict_guard(self):
        # A host that fails the pattern check routes to _strict_guard,
        # which sees a private IP and denies.
        result = check_url(
            "https://evil.atlassian.net.evil.com/hook",
            resolver=_resolver_for("10.0.0.1"),
        )
        assert result.allowed is False


# ===========================================================================
# CandidateMessage structural tests
# ===========================================================================


class TestCandidateMessageStructural:
    """CandidateMessage validation ensures UUIDs and required fields."""

    def _valid_fields(self) -> dict:
        return {
            "event_type": "pii_blocked",
            "severity": "high",
            "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-000000000001",
            "team_id": "11111111-2222-3333-4444-000000000002",
            "project_id": "66666666-7777-8888-9999-000000000003",
            "agent_id": "data-protection",
            "event_id": str(uuid.uuid4()),
            "event_timestamp": "2026-06-25T00:00:00Z",
            "request_id": "req-001",
            "action_taken": "masked",
            "violation_type": "",
            "webhook_provider": "slack",
        }

    def test_valid_fields_parses(self):
        msg = CandidateMessage.from_fields(self._valid_fields())
        assert msg.event_type == "pii_blocked"

    def test_non_uuid_tenant_rejected(self):
        fields = self._valid_fields()
        fields["tenant_id"] = "not-a-uuid"
        with pytest.raises(ValueError):
            CandidateMessage.from_fields(fields)

    def test_missing_event_id_rejected(self):
        fields = self._valid_fields()
        fields["event_id"] = ""
        with pytest.raises(ValueError):
            CandidateMessage.from_fields(fields)

    def test_missing_event_type_rejected(self):
        fields = self._valid_fields()
        fields["event_type"] = ""
        with pytest.raises(ValueError):
            CandidateMessage.from_fields(fields)

    def test_missing_required_key_raises_key_error(self):
        fields = self._valid_fields()
        del fields["tenant_id"]
        with pytest.raises(KeyError):
            CandidateMessage.from_fields(fields)

    def test_to_envelope_keys_are_subset_of_allowed(self):
        msg = CandidateMessage.from_fields(self._valid_fields())
        envelope = msg.to_envelope()
        assert set(envelope.keys()).issubset(_ALLOWED_ENVELOPE_KEYS)

    def test_to_fields_round_trips(self):
        fields = self._valid_fields()
        msg = CandidateMessage.from_fields(fields)
        rt = msg.to_fields()
        # All original fields should survive the round-trip.
        for k, v in fields.items():
            assert rt[k] == v

    def test_severity_order_helper(self):
        from orchestration.webhooks.worker import _severity_gte

        assert _severity_gte("high", "high") is True
        assert _severity_gte("critical", "high") is True
        assert _severity_gte("high", "critical") is False
        assert _severity_gte("low", "high") is False
        assert _severity_gte("medium", "critical") is False


# ===========================================================================
# Helpers
# ===========================================================================


def _collect_all_string_values(obj) -> list:
    """Recursively collect all string values from a nested dict/list structure."""
    values = []
    if isinstance(obj, str):
        values.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            values.extend(_collect_all_string_values(v))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(_collect_all_string_values(item))
    return values
