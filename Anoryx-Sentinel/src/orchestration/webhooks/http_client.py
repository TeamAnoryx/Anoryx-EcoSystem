"""Guarded httpx client for outbound webhook delivery (F-020, ADR-0023 §5.3/§7).

Builds an httpx.AsyncClient that:
  - Connects to the PINNED IP (from GuardResult.pinned_ip) to defeat DNS-rebind
    at connect time (§7 hardening point 2 / vector 3).
  - Forces TLS SNI to the ORIGINAL hostname AND validates the server certificate
    against that hostname (not the IP literal in the URL) by injecting the
    ``sni_hostname`` request extension on every outbound request via an event
    hook.  This is the httpx ≥0.24 mechanism for overriding both SNI and the
    certificate-verification host simultaneously — tested with httpx 0.28.1.
  - Sets the ``Host`` header to the original hostname so the remote server
    receives the canonical hostname even though the TCP socket connects to the
    pinned IP.
  - Uses follow_redirects=False (§7 hardening point 3 / vector 4).
  - Uses verify=True (system CA bundle) — TLS verification is NEVER skipped.
  - Uses explicit bounded timeouts matching the house style from
    src/gateway/router/registry.py:63-69.

How resolve-and-pin + SNI works end-to-end
-------------------------------------------
Without sni_hostname override httpx would validate the server certificate
against the *URL host*, which after resolve-and-pin is a raw IP literal
(e.g. ``151.101.1.229``).  Real providers (hooks.slack.com, *.atlassian.net,
splunk.example.com) issue certificates whose CN/SAN is the *hostname*, not the
IP — so TLS handshake would fail for every real provider.

``sni_hostname`` (httpx ≥0.24, exposed via request.extensions) overrides two
things at once:

  1. The TLS ``server_name`` extension (SNI) sent in the ClientHello — so the
     remote server selects the correct virtual-host certificate.
  2. The hostname used by h11/h2 + the underlying ssl.SSLContext to verify the
     certificate CN/SAN.

The event hook ``_inject_sni`` is registered on the client as a
``request`` hook so it fires on EVERY request the client makes, making it
impossible for a caller to forget it.  ``request.extensions`` is a plain dict;
setting ``sni_hostname`` to the *bytes*-encoded original hostname before the
request is sent is all that is required.

The caller (dispatcher worker) is responsible for calling url_guard.check_url()
BEFORE constructing a client and MUST use the pinned_ip returned by the guard.

NEVER log: target URLs, raw error messages, response body content, or any
field not in the bounded metadata projection (D1).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx

from orchestration.webhooks.config import get_webhook_settings


@asynccontextmanager
async def guarded_http_client(
    *,
    pinned_ip: str,
    hostname: str,
    port: int = 443,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Yield an httpx.AsyncClient pre-wired to the pinned IP with correct SNI/cert/Host.

    Parameters
    ----------
    pinned_ip:
        The IP address from GuardResult.pinned_ip (resolve-and-pin).  The TCP
        socket connects here directly, bypassing all further DNS resolution.
    hostname:
        The original hostname — used for:
          * The ``Host`` request header (so the remote server sees the
            canonical hostname).
          * The ``sni_hostname`` request extension (injected automatically on
            every request via an event hook) so that httpx:
              (a) sends the correct SNI in the TLS ClientHello, and
              (b) validates the server certificate against ``hostname`` (not
                  the raw IP in the URL).
        Certificate validation therefore succeeds for real providers whose
        cert CN/SAN is the hostname (e.g. hooks.slack.com), not the IP.
    port:
        Target port (default 443). The URL guard already validated this.

    Usage
    -----
        guard = check_url(target_url)
        async with guarded_http_client(pinned_ip=guard.pinned_ip,
                                       hostname=guard.hostname) as client:
            resp = await client.post(f"/{path}", ...)
    """
    settings = get_webhook_settings()
    timeout = httpx.Timeout(settings.webhook_http_timeout_seconds)

    # Encode hostname once — sni_hostname extension requires bytes.
    sni_hostname_bytes: bytes = hostname.encode("idna")

    async def _inject_sni(request: httpx.Request) -> None:
        """Event hook: inject sni_hostname into every request before it is sent.

        httpx 0.24+ exposes request.extensions as a mutable dict.  Setting
        ``sni_hostname`` (bytes) causes the underlying SSL layer to use that
        value as both the TLS SNI server_name AND the certificate verification
        hostname, overriding the URL host (which is the raw pinned IP).

        Registering this as a ``request`` event hook means it fires on every
        request the client makes — callers cannot omit it by accident.
        """
        request.extensions["sni_hostname"] = sni_hostname_bytes

    # Base URL points to the pinned IP — all TCP connections go here directly,
    # defeating DNS-rebind at the connect layer (§7 hardening point 2).
    scheme = "https"
    base_url = f"{scheme}://{pinned_ip}:{port}"

    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=False,  # §7 hardening point 3 / vector 4
        headers={
            # Override Host so the remote server sees the canonical hostname.
            "Host": hostname,
        },
        verify=True,  # system CA bundle — TLS verification is never skipped
        event_hooks={"request": [_inject_sni]},
    ) as client:
        yield client
