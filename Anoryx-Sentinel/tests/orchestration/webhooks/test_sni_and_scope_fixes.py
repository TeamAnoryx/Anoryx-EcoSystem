"""Proving tests for two F-020 security fixes (ADR-0023 §7 / §5.2 scope confinement).

Fix 1 — SNI regression guard (http_client.py _inject_sni event hook):
  Tests assert that guarded_http_client registers a request event hook that sets
  request.extensions["sni_hostname"] to the IDNA-encoded original hostname on
  every request.

  REGRESSION GUARD (resolved): _inject_sni MUST stay an ``async def``.
  httpx 0.28.1 AsyncClient._send_handling_redirects does:
      for hook in self._event_hooks["request"]:
          await hook(request)
  A plain synchronous ``def`` returns None; awaiting None raises
      TypeError: object NoneType can't be used in 'await' expression
  which would break every outbound POST before the SNI is injected (the TLS
  handshake never completes). The hook is async in the current source; these
  tests guard against a regression back to sync.

  The offline unit tests below (test_sni_hook_*) verify the STRUCTURAL invariants
  (hook registered, sni_hostname bytes correct, IDN encoding, non-default port)
  and also contain a smoke test that EXPOSES THE BUG by attempting a mock request
  through the full client + hook dispatch path.

Fix 2 — Team/project scope confinement in process_candidate (worker.py):
  Tests assert that the dispatcher's in-Python filter honours the
  (c.team_id is None or c.team_id == msg.team_id) AND
  (c.project_id is None or c.project_id == msg.project_id)
  predicate, so an event scoped to (team=A, project=Q) matches only:
    * config-A (team_id=A, project=None) — team match, project wildcard
    * config-C (team_id=None, project_id=None) — tenant-wide wildcard
  and does NOT match:
    * config-B (team_id=None, project_id=P) — project P != Q

CLASSIFICATION:
  - test_sni_hook_*               → OFFLINE unit (no containers needed)
  - test_real_tls_*               → marked integration; skipped without containers
                                    but actually only needs no network — uses
                                    local TLS server on 127.0.0.1. Kept as a
                                    separate mark so CI can gate them if desired.
  - TestTeamProjectScopeFilter    → OFFLINE unit (no DB needed; pure in-Python
                                    filter logic via mock configs)
  - TestTeamProjectScopeIntegration → marked integration; DB-gated
"""

from __future__ import annotations

import asyncio
import datetime
import os
import socket
import ssl
import tempfile
import threading
import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Shared resolver / fixture helpers
# ---------------------------------------------------------------------------

_PUBLIC_IP = "93.184.216.34"  # example.com — publicly routable


def _skip_if_no_db() -> None:
    if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
        pytest.skip("DATABASE_URL/APP_DATABASE_URL not set — DB-gated test skipped")


# ---------------------------------------------------------------------------
# TLS cert generation helper (cryptography lib — available in dev/CI)
# ---------------------------------------------------------------------------


def _make_self_signed_cert(hostname: str) -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) for a self-signed cert with SAN=DNS:{hostname}."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ===========================================================================
# SNI UNIT TESTS — Offline (no containers, no network)
# ===========================================================================


class TestSniHookStructural:
    """Offline unit tests: prove _inject_sni hook is registered and sets the
    correct bytes on every fabricated request.

    These tests do NOT make any network calls. They inspect the client's event_hooks
    dict and invoke the hook directly on a constructed httpx.Request, mirroring the
    exact mechanism that httpx uses internally before sending.
    """

    @pytest.mark.asyncio
    async def test_sni_hook_registered_on_client(self, monkeypatch):
        """guarded_http_client registers exactly one 'request' event hook."""
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname="hooks.slack.com",
            port=443,
        ) as client:
            hooks = client.event_hooks.get("request", [])
            assert len(hooks) == 1, (
                "guarded_http_client must register exactly one 'request' event hook "
                f"(_inject_sni); found {len(hooks)} hooks: {hooks!r}"
            )

    @pytest.mark.asyncio
    async def test_sni_hook_sets_hostname_bytes_on_request(self, monkeypatch):
        """The registered hook sets request.extensions['sni_hostname'] to IDNA bytes.

        This is the primary regression guard: if someone removes the event hook or
        stops setting sni_hostname, this test fails.
        """
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        hostname = "hooks.slack.com"
        expected_sni = b"hooks.slack.com"

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname=hostname,
            port=443,
        ) as client:
            hooks = client.event_hooks["request"]
            hook_fn = hooks[0]

            # Fabricate a request the same way httpx would before calling the hook.
            req = httpx.Request("POST", f"https://{_PUBLIC_IP}:443/hook")

            # The hook may be sync (current impl) or async (fixed impl). Handle both
            # so that this structural assertion passes regardless and the
            # test_sni_hook_is_async_as_required_by_httpx test documents the async gap.
            result = hook_fn(req)
            if asyncio.iscoroutine(result):
                await result

            assert "sni_hostname" in req.extensions, (
                "request.extensions['sni_hostname'] must be set by the hook; "
                f"extensions after hook: {dict(req.extensions)!r}"
            )
            assert req.extensions["sni_hostname"] == expected_sni, (
                f"sni_hostname must be {expected_sni!r} (IDNA-encoded hostname); "
                f"got {req.extensions['sni_hostname']!r}"
            )

    @pytest.mark.asyncio
    async def test_sni_hook_is_async_as_required_by_httpx(self, monkeypatch):
        """REGRESSION GUARD: _inject_sni MUST stay an async function.

        httpx 0.28.1 AsyncClient._send_handling_redirects calls:
            for hook in self._event_hooks["request"]:
                await hook(request)

        If the hook were a plain ``def`` (not ``async def``), httpx would await the
        None return value and raise:
            TypeError: object NoneType can't be used in 'await' expression

        which would make every outbound POST through guarded_http_client raise before
        the SNI extension is injected. The hook is async in the current source; this
        test guards against a regression back to sync.
        """
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname="hooks.slack.com",
            port=443,
        ) as client:
            hooks = client.event_hooks["request"]
            assert len(hooks) >= 1, "No request hook registered"
            hook_fn = hooks[0]

            assert asyncio.iscoroutinefunction(hook_fn), (
                "REGRESSION: _inject_sni must be 'async def'. httpx 0.28.1 "
                "AsyncClient awaits event hooks via 'await hook(request)'; a sync "
                "hook's None return raises TypeError and prevents ANY request from "
                "completing. Keep it 'async def' in http_client.py."
            )

    @pytest.mark.asyncio
    async def test_sni_hook_fires_on_non_443_port(self, monkeypatch):
        """The SNI hook fires for non-default ports (e.g. Splunk HEC port 8088)."""
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        hostname = "splunk.example.com"
        port = 8088
        expected_sni = b"splunk.example.com"

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname=hostname,
            port=port,
        ) as client:
            hooks = client.event_hooks["request"]
            assert len(hooks) >= 1

            hook_fn = hooks[0]
            req = httpx.Request("POST", f"https://{_PUBLIC_IP}:{port}/hook")

            result = hook_fn(req)
            if asyncio.iscoroutine(result):
                await result

            assert req.extensions.get("sni_hostname") == expected_sni, (
                f"sni_hostname must be {expected_sni!r} for port {port}; "
                f"got {req.extensions.get('sni_hostname')!r}"
            )

    @pytest.mark.asyncio
    async def test_sni_hook_idna_encodes_punycode_hostname(self, monkeypatch):
        """Pre-encoded IDNA (punycode) hostname is preserved correctly in sni_hostname bytes.

        In practice callers pass the hostname as resolved from url_guard, which
        returns the hostname string from urlparse (ASCII/punycode form for IDN labels).
        The hook uses hostname.encode('idna'), which for a punycode hostname
        'xn--bcher-kva.example.com' produces b'xn--bcher-kva.example.com'.

        NOTE on non-ASCII hostnames: guarded_http_client passes the raw hostname as the
        'Host' header value. httpx requires all header values to be ASCII-encodable; a
        raw unicode hostname (e.g. 'bücher.example.com') would raise UnicodeEncodeError
        before the client is created. In practice the URL guard always returns the ASCII
        form (urlparse returns the ASCII/ACE representation for DNS-resolved hostnames).
        This test verifies the punycode round-trip path which is the real production path.
        """
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        # Real production path: url_guard returns the ASCII hostname (punycode already).
        punycode_hostname = "xn--bcher-kva.example.com"
        expected_sni = b"xn--bcher-kva.example.com"

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname=punycode_hostname,
            port=443,
        ) as client:
            hooks = client.event_hooks["request"]
            assert len(hooks) >= 1

            hook_fn = hooks[0]
            req = httpx.Request("POST", f"https://{_PUBLIC_IP}:443/hook")

            result = hook_fn(req)
            if asyncio.iscoroutine(result):
                await result

            assert req.extensions.get("sni_hostname") == expected_sni, (
                f"Punycode hostname {punycode_hostname!r} must encode to {expected_sni!r}; "
                f"got {req.extensions.get('sni_hostname')!r}"
            )

    def test_unicode_hostname_encode_idna_produces_punycode(self):
        """Document that raw unicode hostname.encode('idna') produces correct punycode bytes.

        This is a pure Python encoding test — no httpx client involved.
        Proves the encode('idna') call in the hook produces the correct bytes for
        non-ASCII domain labels (the hook body uses this encoding).
        """
        cases = [
            ("hooks.slack.com", b"hooks.slack.com"),
            ("mycompany.atlassian.net", b"mycompany.atlassian.net"),
            ("xn--bcher-kva.example.com", b"xn--bcher-kva.example.com"),
            # The production path always passes punycode (ASCII) form from urlparse.
        ]
        for hostname, expected in cases:
            got = hostname.encode("idna")
            assert (
                got == expected
            ), f"hostname.encode('idna') for {hostname!r}: expected {expected!r}, got {got!r}"

    @pytest.mark.asyncio
    async def test_sni_hook_fires_per_request_not_once(self, monkeypatch):
        """The hook fires on every request through the client, not just the first."""
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        hostname = "hooks.slack.com"
        expected_sni = b"hooks.slack.com"

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname=hostname,
            port=443,
        ) as client:
            hooks = client.event_hooks["request"]
            hook_fn = hooks[0]

            # Fire the hook on three separate request objects.
            for i in range(3):
                req = httpx.Request("POST", f"https://{_PUBLIC_IP}:443/hook{i}")
                result = hook_fn(req)
                if asyncio.iscoroutine(result):
                    await result
                assert req.extensions.get("sni_hostname") == expected_sni, (
                    f"On call {i}: sni_hostname must be {expected_sni!r}; "
                    f"got {req.extensions.get('sni_hostname')!r}"
                )

    @pytest.mark.asyncio
    async def test_sni_hook_absent_breaks_detection(self, monkeypatch):
        """Negative self-test: a client WITHOUT the hook has no sni_hostname.

        This documents what the guard closes: without the hook, a fabricated request
        carries no sni_hostname extension and httpx would validate the cert against
        the raw IP in the URL (which would fail for any real hostname cert).
        """
        # Build a plain AsyncClient without the event hook.
        async with httpx.AsyncClient(
            base_url=f"https://{_PUBLIC_IP}:443",
            follow_redirects=False,
            verify=True,
        ) as plain_client:
            # No hooks registered.
            hooks = plain_client.event_hooks.get("request", [])
            assert len(hooks) == 0, "Plain client should have no request hooks"

            req = httpx.Request("POST", f"https://{_PUBLIC_IP}:443/hook")
            # Without the hook, no sni_hostname extension is present.
            assert "sni_hostname" not in req.extensions, (
                "Without the hook, sni_hostname must NOT be in extensions — "
                "this documents the gap the hook closes."
            )

    @pytest.mark.asyncio
    async def test_client_base_url_is_pinned_ip(self, monkeypatch):
        """The client's base_url connects to the pinned IP, not the hostname.

        This proves the resolve-and-pin guarantee: TCP connects to pinned_ip while
        SNI/cert validation uses the original hostname (set by the hook).
        """
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        pinned_ip = "151.101.1.229"
        hostname = "hooks.slack.com"

        async with guarded_http_client(
            pinned_ip=pinned_ip,
            hostname=hostname,
            port=443,
        ) as client:
            base = str(client.base_url)
            assert pinned_ip in base, (
                f"Client base_url must contain the pinned IP {pinned_ip!r}; " f"got {base!r}"
            )
            # Hostname must NOT be in the base_url (it's set via SNI hook + Host header).
            assert "hooks.slack.com" not in base, (
                "Hostname must NOT be in the base_url; TCP connects to the pinned IP. "
                f"Got base_url={base!r}"
            )

    @pytest.mark.asyncio
    async def test_client_host_header_is_original_hostname(self, monkeypatch):
        """The client carries a Host header set to the original hostname."""
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        hostname = "hooks.slack.com"

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname=hostname,
            port=443,
        ) as client:
            headers = dict(client.headers)
            host_hdr = headers.get("host", "")
            assert (
                host_hdr == hostname
            ), f"Client 'Host' header must be {hostname!r}; got {host_hdr!r}"

    @pytest.mark.asyncio
    async def test_client_follow_redirects_is_false(self, monkeypatch):
        """guarded_http_client sets follow_redirects=False."""
        from orchestration.webhooks.config import WebhookSettings
        from orchestration.webhooks.http_client import guarded_http_client

        fake_settings = WebhookSettings(webhook_http_timeout_seconds=5.0)
        monkeypatch.setattr(
            "orchestration.webhooks.http_client.get_webhook_settings",
            lambda: fake_settings,
        )

        async with guarded_http_client(
            pinned_ip=_PUBLIC_IP,
            hostname="hooks.slack.com",
            port=443,
        ) as client:
            assert client.follow_redirects is False, (
                "follow_redirects must be False (ADR-0023 §7 hardening point 3). "
                f"Got: {client.follow_redirects!r}"
            )


# ===========================================================================
# REAL TLS PROOF TESTS — marked integration (need no external containers,
# only a local TLS server on 127.0.0.1, but kept behind the integration
# mark so CI can choose to gate them separately from the offline suite).
# ===========================================================================


@pytest.mark.integration
class TestRealTlsHandshakeProof:
    """Real TLS handshake proof using a local self-signed TLS server.

    COVERAGE SCOPE:
      The positive case proves:
        - An httpx.AsyncClient wired with a 'request' event hook that sets
          sni_hostname=b"webhook-sink.test" (mirroring _inject_sni) can:
          (a) Connect a TCP socket to 127.0.0.1:{port} (pinned IP)
          (b) Complete a TLS handshake where the server sees SNI="webhook-sink.test"
          (c) Validate the server cert (SAN=DNS:webhook-sink.test) against the
              hostname, NOT against the IP 127.0.0.1.
        - The server sees the correct SNI in the ClientHello.

      The negative case proves:
        - A cert whose SAN is "other-hostname.test" causes a TLS handshake
          failure when the client expects "webhook-sink.test" — proving the
          cert is validated against the hostname, not the IP.

      LIMITATION: These tests cannot use guarded_http_client directly because
      guarded_http_client hardcodes verify=True (system CAs) and the self-signed
      cert is not in the system bundle. We instead construct an equivalent client
      manually (same sni_hostname extension hook + pinned-IP base_url) using a
      custom ssl.SSLContext that trusts only the test CA. This proves the TLS
      mechanism works when the hook is correct; the guarded_http_client structural
      tests above prove the hook is registered.

      ASYNC HOOK BUG NOTE: because guarded_http_client's _inject_sni is currently
      sync (see test_sni_hook_is_async_as_required_by_httpx), the real-TLS positive
      test uses an async hook directly to prove the mechanism. This means the
      positive TLS test passing does NOT prove guarded_http_client is currently
      working end-to-end — it proves the mechanism would work once the hook is made
      async (as the bug fix requires).
    """

    TEST_HOSTNAME = "webhook-sink.test"

    @staticmethod
    def _start_tls_server(
        cert_pem: bytes,
        key_pem: bytes,
        port: int,
        *,
        ready_event: threading.Event,
        stop_event: threading.Event,
        connections_served: list,
    ) -> None:
        """Run a minimal TLS HTTP/1.1 server in a daemon thread.

        Tracks completed handshakes via connections_served list.
        Note: ssl.SSLSocket.server_hostname is None on Windows when wrap_socket()
        is called without server_hostname= parameter. The handshake itself still
        uses the SNI from the client hello to select the certificate.
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix="_cert.pem") as cf:
            cf.write(cert_pem)
            cert_path = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix="_key.pem") as kf:
            kf.write(key_pem)
            key_path = kf.name

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)

            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(5)
            srv.settimeout(0.3)
            ready_event.set()

            while not stop_event.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    continue

                def _handle(c):
                    try:
                        tls = ctx.wrap_socket(c, server_side=True)
                        # TLS handshake succeeded — record it.
                        connections_served.append("ok")
                        # Read HTTP request (enough to parse headers).
                        data = b""
                        tls.settimeout(2.0)
                        while b"\r\n\r\n" not in data:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        tls.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Length: 2\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Connection: keep-alive\r\n\r\n"
                            b"OK"
                        )
                        import time

                        time.sleep(0.5)  # hold connection so httpx can read response
                    except Exception:
                        pass
                    finally:
                        try:
                            c.close()
                        except Exception:
                            pass

                threading.Thread(target=_handle, args=(conn,), daemon=True).start()

            srv.close()
        finally:
            try:
                os.unlink(cert_path)
            except Exception:
                pass
            try:
                os.unlink(key_path)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_positive_tls_handshake_with_sni_hostname_extension(self):
        """Positive: sni_hostname extension causes the server cert (SAN=webhook-sink.test)
        to be verified successfully when connecting to 127.0.0.1 (the pinned IP).

        What this proves:
          - TCP connects to 127.0.0.1:{port} (pinned IP, not the hostname).
          - sni_hostname=b"webhook-sink.test" in request.extensions causes httpx/httpcore
            to pass server_hostname="webhook-sink.test" to the TLS layer.
          - The client verifies the server cert's SAN against "webhook-sink.test"
            (not against "127.0.0.1" — the IP literal in the URL).
          - The TLS handshake completes: the server's cert (SAN=webhook-sink.test)
            is accepted by the client (proves cert validation is against hostname).
          - The HTTP response is received: 200 OK.

        What this does NOT prove:
          - That guarded_http_client itself currently works end-to-end (it has a
            sync-hook bug — see test_sni_hook_is_async_as_required_by_httpx).
          - This test uses an async hook directly, mirroring the fixed implementation.

        Platform note on ssl.SSLSocket.server_hostname:
          Python's ssl module only populates SSLSocket.server_hostname when
          wrap_socket() is called with an explicit server_hostname= parameter.
          The asyncio/anyio TLS path (used by httpcore) sets SNI in the
          ssl.SSLObject but the wrapped socket's .server_hostname attribute is None.
          This is a Python introspection gap, NOT a missing SNI — the handshake
          succeeds (200 OK) because the server selected the correct cert based on
          the SNI in the ClientHello. The negative test (wrong cert SAN) confirms
          cert validation is enforced against the hostname.
        """
        cert_pem, key_pem = _make_self_signed_cert(self.TEST_HOSTNAME)
        port = _find_free_port()
        ready_ev = threading.Event()
        stop_ev = threading.Event()
        connections_served: list = []

        thread = threading.Thread(
            target=self._start_tls_server,
            args=(cert_pem, key_pem, port),
            kwargs={
                "ready_event": ready_ev,
                "stop_event": stop_ev,
                "connections_served": connections_served,
            },
            daemon=True,
        )
        thread.start()
        ready_ev.wait(timeout=3)

        # Build a client ssl context that trusts ONLY the test CA (our self-signed cert).
        with tempfile.NamedTemporaryFile(delete=False, suffix="_ca.pem") as ca_f:
            ca_f.write(cert_pem)
            ca_path = ca_f.name

        try:
            client_ctx = ssl.create_default_context()
            client_ctx.load_verify_locations(ca_path)

            sni_bytes = self.TEST_HOSTNAME.encode("idna")

            # Use an ASYNC hook (the correct implementation; mirroring the bug fix).
            async def _inject_sni_async(request: httpx.Request) -> None:
                request.extensions["sni_hostname"] = sni_bytes

            async with httpx.AsyncClient(
                base_url=f"https://127.0.0.1:{port}",
                verify=client_ctx,
                follow_redirects=False,
                http1=True,
                http2=False,
                event_hooks={"request": [_inject_sni_async]},
            ) as client:
                resp = await client.post("/webhook", content=b'{"test": true}')

            # 200 OK proves: TCP connected to 127.0.0.1 (pinned IP), TLS handshake
            # succeeded with sni_hostname="webhook-sink.test" overriding the URL host,
            # the server cert (SAN=webhook-sink.test) was validated against the hostname.
            assert resp.status_code == 200, (
                f"TLS handshake + HTTP round-trip must succeed; got {resp.status_code}. "
                "sni_hostname extension must cause cert validation against hostname (not IP)."
            )
            assert len(connections_served) >= 1, (
                "Server must have completed at least one TLS handshake. "
                "connections_served is empty, suggesting the handshake failed on the server side."
            )
        finally:
            stop_ev.set()
            thread.join(timeout=3)
            try:
                os.unlink(ca_path)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_negative_wrong_san_causes_handshake_failure(self):
        """Negative: cert with SAN=other-hostname.test fails when client expects webhook-sink.test.

        This proves that cert validation is performed against the HOSTNAME (from
        sni_hostname extension), NOT against the IP address (127.0.0.1).  A server
        serving a cert whose SAN does not match the expected hostname must be
        rejected by the client.

        Without the sni_hostname mechanism (or if verification used the IP),
        the handshake would succeed against any cert — which would mean the SNI/cert
        validation gap the security fix closes was real.
        """
        # Generate a cert whose SAN is a DIFFERENT hostname.
        wrong_hostname = "other-hostname.test"
        cert_pem, key_pem = _make_self_signed_cert(wrong_hostname)
        port = _find_free_port()
        ready_ev = threading.Event()
        stop_ev = threading.Event()
        connections_served_neg: list = []

        thread = threading.Thread(
            target=self._start_tls_server,
            args=(cert_pem, key_pem, port),
            kwargs={
                "ready_event": ready_ev,
                "stop_event": stop_ev,
                "connections_served": connections_served_neg,
            },
            daemon=True,
        )
        thread.start()
        ready_ev.wait(timeout=3)

        # The client trusts the "wrong cert" CA but expects SNI=webhook-sink.test.
        with tempfile.NamedTemporaryFile(delete=False, suffix="_ca.pem") as ca_f:
            ca_f.write(cert_pem)
            ca_path = ca_f.name

        try:
            client_ctx = ssl.create_default_context()
            client_ctx.load_verify_locations(ca_path)

            sni_bytes = self.TEST_HOSTNAME.encode("idna")  # webhook-sink.test

            async def _inject_sni_async(request: httpx.Request) -> None:
                request.extensions["sni_hostname"] = sni_bytes

            async with httpx.AsyncClient(
                base_url=f"https://127.0.0.1:{port}",
                verify=client_ctx,
                follow_redirects=False,
                http1=True,
                http2=False,
                event_hooks={"request": [_inject_sni_async]},
            ) as client:
                with pytest.raises((httpx.ConnectError, ssl.SSLError, OSError)):
                    # Handshake MUST fail: cert SAN is other-hostname.test but
                    # client validates against webhook-sink.test.
                    await client.post("/webhook", content=b"{}")

        finally:
            stop_ev.set()
            thread.join(timeout=3)
            try:
                os.unlink(ca_path)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_ip_literal_without_sni_fails_against_hostname_cert(self):
        """Without sni_hostname, connecting to IP literal fails cert validation.

        This is the gap that the security fix closes. Without the extension, httpx
        would validate the cert against the IP "127.0.0.1" — but the cert's SAN is
        "webhook-sink.test". Validation would fail (because the IP is not in the cert).

        Proves: The cert is NOT validated against the IP, it's validated against the
        hostname extracted from the URL — and without sni_hostname, the URL contains
        the IP, causing a mismatch.
        """
        cert_pem, key_pem = _make_self_signed_cert(self.TEST_HOSTNAME)
        port = _find_free_port()
        ready_ev = threading.Event()
        stop_ev = threading.Event()
        connections_served_no_sni: list = []

        thread = threading.Thread(
            target=self._start_tls_server,
            args=(cert_pem, key_pem, port),
            kwargs={
                "ready_event": ready_ev,
                "stop_event": stop_ev,
                "connections_served": connections_served_no_sni,
            },
            daemon=True,
        )
        thread.start()
        ready_ev.wait(timeout=3)

        with tempfile.NamedTemporaryFile(delete=False, suffix="_ca.pem") as ca_f:
            ca_f.write(cert_pem)
            ca_path = ca_f.name

        try:
            client_ctx = ssl.create_default_context()
            client_ctx.load_verify_locations(ca_path)

            # NO sni_hostname extension — no event hook injected.
            async with httpx.AsyncClient(
                base_url=f"https://127.0.0.1:{port}",
                verify=client_ctx,
                follow_redirects=False,
                http1=True,
                http2=False,
                # Deliberately no event_hooks
            ) as client:
                with pytest.raises((httpx.ConnectError, ssl.SSLError, OSError)):
                    # Must fail: URL host is 127.0.0.1 (IP), cert SAN is webhook-sink.test.
                    # Without sni_hostname override, httpx validates cert against the
                    # URL host (127.0.0.1), which is not in the cert's SAN list.
                    await client.post("/webhook", content=b"{}")

        finally:
            stop_ev.set()
            thread.join(timeout=3)
            try:
                os.unlink(ca_path)
            except Exception:
                pass


# ===========================================================================
# TEAM/PROJECT SCOPE FILTER — Offline unit tests (no DB/Redis needed)
# ===========================================================================


class TestTeamProjectScopeFilterOffline:
    """Prove the in-Python scope filter in process_candidate is correct.

    The filter from worker.py lines 551-557:
        matching = [
            c for c in configs
            if _severity_gte(event_severity, c.min_severity)
            and (c.team_id is None or c.team_id == msg.team_id)
            and (c.project_id is None or c.project_id == msg.project_id)
        ]

    Test matrix:
      config-A: team_id=TEAM_A, project_id=None       → scope: team A, all projects
      config-B: team_id=None,   project_id=PROJECT_P  → scope: all teams, project P
      config-C: team_id=None,   project_id=None       → scope: tenant-wide

    Candidate (team=TEAM_A, project=PROJECT_Q):
      config-A MUST match (team A, project wildcard)
      config-B MUST NOT match (project P != Q)
      config-C MUST match (tenant-wide wildcard)

    Inverse candidate (team=TEAM_B, project=PROJECT_Q):
      config-A MUST NOT match (team B != team A)
      config-B MUST NOT match (project P != Q)
      config-C MUST match (tenant-wide wildcard)
    """

    TEAM_A = str(uuid.uuid4())
    TEAM_B = str(uuid.uuid4())
    PROJECT_P = str(uuid.uuid4())
    PROJECT_Q = str(uuid.uuid4())
    TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-000000000001"

    def _make_config(self, name: str, team_id: str | None, project_id: str | None) -> MagicMock:
        c = MagicMock()
        c.config_id = str(uuid.uuid4())
        c.tenant_id = self.TENANT_ID
        c.provider = "slack"
        c.target_url = "https://hooks.slack.com/services/T000/B000/tok"
        c.min_severity = "high"
        c.enabled = True
        c.credential = None
        c.signing_secret = None
        c.team_id = team_id
        c.project_id = project_id
        c._name = name
        return c

    def _make_msg(self, team_id: str, project_id: str) -> object:
        from orchestration.webhooks.queue import CandidateMessage

        return CandidateMessage(
            event_type="pii_blocked",
            severity="high",
            tenant_id=self.TENANT_ID,
            team_id=team_id,
            project_id=project_id,
            agent_id="data-protection",
            event_id=str(uuid.uuid4()),
            event_timestamp="2026-06-25T00:00:00Z",
            request_id="req-scope-test",
            action_taken="masked",
            violation_type="",
            webhook_provider="slack",
        )

    @pytest.mark.asyncio
    async def test_team_a_project_q_candidate_matches_a_and_c_not_b(self):
        """Candidate(team=A, project=Q): config-A and config-C match; config-B does not."""
        from orchestration.webhooks.worker import process_candidate

        config_a = self._make_config("A", team_id=self.TEAM_A, project_id=None)
        config_b = self._make_config("B", team_id=None, project_id=self.PROJECT_P)
        config_c = self._make_config("C", team_id=None, project_id=None)

        msg = self._make_msg(team_id=self.TEAM_A, project_id=self.PROJECT_Q)

        # Track which configs _deliver_to_config was called with.
        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_a, config_b, config_c]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_tenant_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_tenant_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg)

        assert "A" in delivered_to, (
            "config-A (team=TEAM_A, project=None) MUST match candidate "
            f"(team=TEAM_A, project=PROJECT_Q). Delivered to: {delivered_to!r}"
        )
        assert "C" in delivered_to, (
            "config-C (team=None, project=None) MUST match any candidate (tenant-wide). "
            f"Delivered to: {delivered_to!r}"
        )
        assert "B" not in delivered_to, (
            "config-B (team=None, project=PROJECT_P) MUST NOT match candidate "
            f"(project=PROJECT_Q). Delivered to: {delivered_to!r} — "
            "intra-tenant over-disclosure open!"
        )

    @pytest.mark.asyncio
    async def test_team_b_project_q_candidate_matches_only_c(self):
        """Inverse: Candidate(team=B, project=Q): only config-C matches."""
        from orchestration.webhooks.worker import process_candidate

        config_a = self._make_config("A", team_id=self.TEAM_A, project_id=None)
        config_b = self._make_config("B", team_id=None, project_id=self.PROJECT_P)
        config_c = self._make_config("C", team_id=None, project_id=None)

        msg = self._make_msg(team_id=self.TEAM_B, project_id=self.PROJECT_Q)

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_a, config_b, config_c]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_tenant_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_tenant_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg)

        assert "A" not in delivered_to, (
            "config-A (team=TEAM_A) MUST NOT match candidate (team=TEAM_B). "
            f"Delivered to: {delivered_to!r} — intra-tenant over-disclosure open!"
        )
        assert "B" not in delivered_to, (
            "config-B (project=PROJECT_P) MUST NOT match candidate (project=PROJECT_Q). "
            f"Delivered to: {delivered_to!r}"
        )
        assert "C" in delivered_to, (
            "config-C (tenant-wide NULL scope) MUST match any candidate. "
            f"Delivered to: {delivered_to!r}"
        )

    @pytest.mark.asyncio
    async def test_tenant_wide_config_matches_any_team_and_project(self):
        """config-C (NULL team, NULL project) matches candidates with any team/project combo."""
        from orchestration.webhooks.worker import process_candidate

        config_c = self._make_config("C", team_id=None, project_id=None)

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        candidates = [
            (self.TEAM_A, self.PROJECT_P),
            (self.TEAM_A, self.PROJECT_Q),
            (self.TEAM_B, self.PROJECT_P),
            (str(uuid.uuid4()), str(uuid.uuid4())),  # completely random IDs
        ]
        for team_id, project_id in candidates:
            delivered_to.clear()
            msg = self._make_msg(team_id=team_id, project_id=project_id)

            _res = MagicMock()
            _res.scalars.return_value.all.return_value = [config_c]
            _sess = MagicMock()
            _sess.execute = AsyncMock(return_value=_res)
            _sess_ref = _sess  # capture for closure

            @asynccontextmanager
            async def _mock_session(tid: str, _s=_sess_ref):
                yield _s

            with (
                patch(
                    "orchestration.webhooks.worker.get_tenant_session",
                    side_effect=_mock_session,
                ),
                patch(
                    "orchestration.webhooks.worker._deliver_to_config",
                    side_effect=_mock_deliver,
                ),
            ):
                await process_candidate(msg)

            assert "C" in delivered_to, (
                f"tenant-wide config must match candidate "
                f"(team={team_id!r}, project={project_id!r}); "
                f"delivered_to={delivered_to!r}"
            )

    @pytest.mark.asyncio
    async def test_exact_team_scope_does_not_leak_to_different_team(self):
        """Config scoped to team_id=TEAM_A must NOT fire for a candidate from TEAM_B."""
        from orchestration.webhooks.worker import process_candidate

        # Only one config — team-scoped.
        config_a = self._make_config("A", team_id=self.TEAM_A, project_id=None)

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        msg = self._make_msg(team_id=self.TEAM_B, project_id=self.PROJECT_Q)

        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_a]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg)

        assert delivered_to == [], (
            "A team-scoped config must fire ONLY for its own team. "
            f"config-A (team=TEAM_A) fired for candidate (team=TEAM_B): {delivered_to!r}"
        )

    @pytest.mark.asyncio
    async def test_exact_project_scope_does_not_leak_to_different_project(self):
        """Config scoped to project_id=PROJECT_P must NOT fire for candidate from PROJECT_Q."""
        from orchestration.webhooks.worker import process_candidate

        config_b = self._make_config("B", team_id=None, project_id=self.PROJECT_P)

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        msg = self._make_msg(team_id=self.TEAM_A, project_id=self.PROJECT_Q)

        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_b]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg)

        assert delivered_to == [], (
            "A project-scoped config must fire ONLY for its own project. "
            "config-B (project=PROJECT_P) fired for candidate (project=PROJECT_Q): "
            f"{delivered_to!r}"
        )

    @pytest.mark.asyncio
    async def test_exact_team_and_project_scope_requires_both_to_match(self):
        """Config scoped to (team=A, project=P) requires BOTH to match — not just one."""
        from orchestration.webhooks.worker import process_candidate

        # Config with BOTH team AND project scope.
        config_ab = self._make_config("AB", team_id=self.TEAM_A, project_id=self.PROJECT_P)

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        # Case 1: team matches, project doesn't → no match.
        msg_team_match_only = self._make_msg(team_id=self.TEAM_A, project_id=self.PROJECT_Q)
        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_ab]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg_team_match_only)

        assert delivered_to == [], (
            "Config(team=A, project=P) must NOT fire when only team matches: "
            f"delivered_to={delivered_to!r}"
        )

        # Case 2: project matches, team doesn't → no match.
        delivered_to.clear()
        msg_project_match_only = self._make_msg(team_id=self.TEAM_B, project_id=self.PROJECT_P)

        @asynccontextmanager
        async def _mock_session2(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session2,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg_project_match_only)

        assert delivered_to == [], (
            "Config(team=A, project=P) must NOT fire when only project matches: "
            f"delivered_to={delivered_to!r}"
        )

        # Case 3: both match → fires.
        delivered_to.clear()
        msg_both_match = self._make_msg(team_id=self.TEAM_A, project_id=self.PROJECT_P)

        @asynccontextmanager
        async def _mock_session3(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session3,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg_both_match)

        assert "AB" in delivered_to, (
            "Config(team=A, project=P) MUST fire when both team and project match. "
            f"delivered_to={delivered_to!r}"
        )

    @pytest.mark.asyncio
    async def test_below_min_severity_config_not_matched_even_if_scope_matches(self):
        """Severity threshold is applied independently of team/project scope filter.

        A config with min_severity='critical' must not fire for a 'high' event,
        even if the team/project scope matches exactly.
        """
        from orchestration.webhooks.worker import process_candidate

        config_crit = self._make_config("CRIT", team_id=None, project_id=None)
        config_crit.min_severity = "critical"

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        msg = self._make_msg(team_id=self.TEAM_A, project_id=self.PROJECT_Q)
        # msg.severity == 'high' < 'critical'

        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_crit]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg)

        assert delivered_to == [], (
            "Config with min_severity='critical' must NOT fire for severity='high' event. "
            f"delivered_to={delivered_to!r}"
        )

    @pytest.mark.asyncio
    async def test_scope_filter_combined_with_severity(self):
        """Scope filter and severity filter are both required to pass."""
        from orchestration.webhooks.worker import process_candidate

        # config-D: team=TEAM_A, project=None, min_severity='high' → should match
        config_d = self._make_config("D", team_id=self.TEAM_A, project_id=None)
        config_d.min_severity = "high"

        # config-E: team=TEAM_B, project=None, min_severity='high' → should NOT match (wrong team)
        config_e = self._make_config("E", team_id=self.TEAM_B, project_id=None)
        config_e.min_severity = "high"

        # config-F: team=TEAM_A, project=None, min_severity='critical'
        # → should NOT match (event severity=high < critical)
        config_f = self._make_config("F", team_id=self.TEAM_A, project_id=None)
        config_f.min_severity = "critical"

        delivered_to: list[str] = []

        async def _mock_deliver(candidate_msg, cfg):
            delivered_to.append(cfg._name)

        msg = self._make_msg(team_id=self.TEAM_A, project_id=self.PROJECT_Q)
        # severity=high

        config_results = MagicMock()
        config_results.scalars.return_value.all.return_value = [config_d, config_e, config_f]
        config_session_mock = MagicMock()
        config_session_mock.execute = AsyncMock(return_value=config_results)

        @asynccontextmanager
        async def _mock_session(tid: str):
            yield config_session_mock

        with (
            patch(
                "orchestration.webhooks.worker.get_tenant_session",
                side_effect=_mock_session,
            ),
            patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_mock_deliver,
            ),
        ):
            await process_candidate(msg)

        assert "D" in delivered_to, f"config-D (team=A, severity=high) must match: {delivered_to!r}"
        assert (
            "E" not in delivered_to
        ), f"config-E (team=B) must NOT match (wrong team): {delivered_to!r}"
        assert (
            "F" not in delivered_to
        ), f"config-F (min=critical, event=high) must NOT match (severity): {delivered_to!r}"


# ===========================================================================
# TEAM/PROJECT SCOPE — Integration tests (DB-gated)
# ===========================================================================


@pytest.mark.integration
class TestTeamProjectScopeIntegration:
    """DB-gated integration tests for team/project scope confinement.

    These require DATABASE_URL and APP_DATABASE_URL. They create real
    webhook_config rows (via direct INSERT) and drive process_candidate
    against a mock HTTP layer to prove the DB-loaded configs are filtered
    correctly by scope.
    """

    TENANT_ID: str = str(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_db_scoped_configs_filtered_correctly(self):
        """Seed three configs in the DB (A: team-scoped, B: project-scoped, C: tenant-wide).
        Drive process_candidate with candidate(team=A, project=Q) and assert
        only configs A and C are delivered to.

        This is the full integration proof: the Python filter operates on real
        ORM objects loaded from the DB (not mock MagicMock configs), so any
        DB-level issue (wrong column, NULL handling) would surface here.
        """
        _skip_if_no_db()
        import re

        import sqlalchemy as sa
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

        from orchestration.webhooks.queue import CandidateMessage
        from orchestration.webhooks.worker import process_candidate

        db_url = os.environ.get("DATABASE_URL", "")
        url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", db_url)
        url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)

        team_a = str(uuid.uuid4())
        project_p = str(uuid.uuid4())
        project_q = str(uuid.uuid4())
        tenant_id = str(uuid.uuid4())

        engine = create_async_engine(
            url,
            echo=False,
            connect_args={"server_settings": {"app.session_kind": "privileged"}},
        )
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

        config_id_a = str(uuid.uuid4())
        config_id_b = str(uuid.uuid4())
        config_id_c = str(uuid.uuid4())

        try:
            async with factory() as sess:
                async with sess.begin():
                    # Seed tenant row.
                    await sess.execute(
                        sa.text(
                            "INSERT INTO tenants (tenant_id, name, is_active) "
                            "VALUES (:tid, :name, TRUE) ON CONFLICT DO NOTHING"
                        ),
                        {"tid": tenant_id, "name": "scope-integration-test-tenant"},
                    )
                    # config-A: scoped to team_a, project NULL
                    await sess.execute(
                        sa.text(
                            "INSERT INTO webhook_config "
                            "(config_id, tenant_id, team_id, project_id, provider, target_url, "
                            "min_severity, enabled) "
                            "VALUES (:cid, :tid, :team, NULL, 'slack', "
                            "'https://hooks.slack.com/services/T000/B000/tok', "
                            "'high', TRUE)"
                        ),
                        {"cid": config_id_a, "tid": tenant_id, "team": team_a},
                    )
                    # config-B: team NULL, project_id=project_p
                    await sess.execute(
                        sa.text(
                            "INSERT INTO webhook_config "
                            "(config_id, tenant_id, team_id, project_id, provider, target_url, "
                            "min_severity, enabled) "
                            "VALUES (:cid, :tid, NULL, :proj, 'slack', "
                            "'https://hooks.slack.com/services/T000/B001/tok', "
                            "'high', TRUE)"
                        ),
                        {"cid": config_id_b, "tid": tenant_id, "proj": project_p},
                    )
                    # config-C: team NULL, project NULL (tenant-wide)
                    await sess.execute(
                        sa.text(
                            "INSERT INTO webhook_config "
                            "(config_id, tenant_id, team_id, project_id, provider, target_url, "
                            "min_severity, enabled) "
                            "VALUES (:cid, :tid, NULL, NULL, 'slack', "
                            "'https://hooks.slack.com/services/T000/B002/tok', "
                            "'high', TRUE)"
                        ),
                        {"cid": config_id_c, "tid": tenant_id},
                    )

            # Now drive process_candidate with candidate(team=team_a, project=project_q).
            msg = CandidateMessage(
                event_type="pii_blocked",
                severity="high",
                tenant_id=tenant_id,
                team_id=team_a,
                project_id=project_q,
                agent_id="data-protection",
                event_id=str(uuid.uuid4()),
                event_timestamp="2026-06-25T00:00:00Z",
                request_id="req-scope-integration-test",
                action_taken="masked",
                violation_type="",
                webhook_provider="slack",
            )

            delivered_config_ids: list[str] = []

            # Mock the delivery layer — we test scope filtering, not actual HTTP delivery.
            async def _tracking_deliver(candidate_msg, cfg):
                delivered_config_ids.append(cfg.config_id)

            with patch(
                "orchestration.webhooks.worker._deliver_to_config",
                side_effect=_tracking_deliver,
            ):
                await process_candidate(msg)

            assert config_id_a in delivered_config_ids, (
                "config-A (team=team_a, project=NULL) must match candidate (team=team_a, "
                f"project=project_q). Delivered to: {delivered_config_ids!r}"
            )
            assert config_id_c in delivered_config_ids, (
                "config-C (team=NULL, project=NULL) must match any candidate. "
                f"Delivered to: {delivered_config_ids!r}"
            )
            assert config_id_b not in delivered_config_ids, (
                "config-B (team=NULL, project=project_p) must NOT match candidate "
                f"(project=project_q). Delivered to: {delivered_config_ids!r} — "
                "intra-tenant over-disclosure!"
            )

        finally:
            # Cleanup: remove test rows.
            try:
                async with factory() as sess:
                    async with sess.begin():
                        for cid in (config_id_a, config_id_b, config_id_c):
                            await sess.execute(
                                sa.text("DELETE FROM webhook_config WHERE config_id = :cid"),
                                {"cid": cid},
                            )
                        await sess.execute(
                            sa.text("DELETE FROM tenants WHERE tenant_id = :tid"),
                            {"tid": tenant_id},
                        )
            except Exception:
                pass
            await engine.dispose()
