"""SSRF endpoint-validation matrix (O-005, ADR-0005) — the load-bearing security property.

A data-driven registry feeds endpoints into outbound httpx calls (health probes + policy
distribution). validate_endpoint() is the single gate: only public https endpoints pass by
default; private / loopback / link-local / cloud-metadata destinations are rejected unless the
operator explicitly allowlists the host. DNS-rebinding is defended by resolving the host and
rejecting if ANY resolved address is blocked. These tests use IP literals (no DNS) and
monkeypatched getaddrinfo (deterministic, offline) so the matrix is hermetic.
"""

from __future__ import annotations

import socket

import pytest

from orchestrator.coordination.endpoint_validation import (
    EndpointValidationError,
    validate_endpoint,
    validate_endpoint_async,
)

_EMPTY: frozenset[str] = frozenset()


# --------------------------------------------------------------------------- #
# Accept: public https endpoints (IP literals — no DNS needed).
# --------------------------------------------------------------------------- #


def test_accepts_public_https_ip_literal() -> None:
    url = "https://8.8.8.8"
    assert validate_endpoint(url, allowlist=_EMPTY, allow_http=False) == url


def test_accepts_public_https_ip_with_port_and_path() -> None:
    url = "https://8.8.8.8:8443/admin/policies/intake"
    assert validate_endpoint(url, allowlist=_EMPTY, allow_http=False) == url


def test_accepts_public_https_hostname_resolving_public(monkeypatch) -> None:
    # Monkeypatch resolution so the test never touches the network: a public A record.
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))]
    )
    url = "https://sentinel.example.com/admin/policies/intake"
    assert validate_endpoint(url, allowlist=_EMPTY, allow_http=False) == url


# --------------------------------------------------------------------------- #
# Reject: scheme.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url", ["ftp://8.8.8.8", "file:///etc/passwd", "gopher://8.8.8.8"])
def test_rejects_non_http_scheme(url: str) -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint(url, allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "scheme_not_allowed"


def test_rejects_http_when_not_allowlisted() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("http://8.8.8.8", allowlist=_EMPTY, allow_http=True)
    # 8.8.8.8 is public but http requires the host be allowlisted too.
    assert exc.value.reason == "http_not_allowed"


def test_rejects_http_when_allow_http_disabled_even_if_allowlisted() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("http://8.8.8.8", allowlist=frozenset({"8.8.8.8"}), allow_http=False)
    assert exc.value.reason == "http_not_allowed"


def test_accepts_http_when_allowlisted_and_allow_http() -> None:
    url = "http://127.0.0.1:8080/admin/policies/intake"
    out = validate_endpoint(url, allowlist=frozenset({"127.0.0.1"}), allow_http=True)
    assert out == url


def test_accepts_http_when_hostport_allowlisted() -> None:
    url = "http://127.0.0.1:8080"
    out = validate_endpoint(url, allowlist=frozenset({"127.0.0.1:8080"}), allow_http=True)
    assert out == url


# --------------------------------------------------------------------------- #
# Reject: malformed / credentials / fragment / host.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url", ["", "   ", None])
def test_rejects_empty(url: str | None) -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint(url, allowlist=_EMPTY, allow_http=False)  # type: ignore[arg-type]
    assert exc.value.reason == "empty_endpoint"


def test_rejects_embedded_credentials() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://user:pass@8.8.8.8", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "embedded_credentials"


def test_rejects_fragment() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://8.8.8.8/path#frag", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "fragment_not_allowed"


def test_rejects_missing_host() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https:///admin", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "missing_host"


def test_rejects_bad_port() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://8.8.8.8:notaport", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "malformed_url"


# --------------------------------------------------------------------------- #
# Reject: private / loopback / link-local / metadata IP literals (SSRF core).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "https://10.0.0.5",  # RFC1918 private
        "https://192.168.1.1",  # RFC1918 private
        "https://172.16.0.1",  # RFC1918 private
        "https://127.0.0.1",  # loopback
        "https://169.254.169.254",  # cloud metadata (link-local)
        "https://[::1]",  # IPv6 loopback
        "https://0.0.0.0",  # unspecified
    ],
)
def test_rejects_blocked_ip_literals(url: str) -> None:
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint(url, allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "blocked_private_ip"


def test_allowlisted_private_ip_is_accepted_over_https() -> None:
    # An operator may explicitly allowlist a loopback/private host; https needs no allow_http.
    url = "https://127.0.0.1:8443"
    out = validate_endpoint(url, allowlist=frozenset({"127.0.0.1"}), allow_http=False)
    assert out == url


# --------------------------------------------------------------------------- #
# Reject: DNS rebinding — a hostname that resolves to a private address.
# --------------------------------------------------------------------------- #


def test_rejects_hostname_resolving_to_private(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://rebind.evil.test", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "blocked_private_ip"


def test_rejects_hostname_with_any_private_in_multiple_records(monkeypatch) -> None:
    # One public + one private A record → reject (the attacker hides a private address).
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://mixed.example.com", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "blocked_private_ip"


def test_rejects_unresolvable_hostname(monkeypatch) -> None:
    def _boom(*a, **k):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://nope.invalid", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "dns_resolution_failed"


def test_localhost_resolves_to_loopback_and_is_rejected() -> None:
    # Real resolution (deterministic on every platform): localhost → loopback → blocked.
    with pytest.raises(EndpointValidationError) as exc:
        validate_endpoint("https://localhost:8443", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "blocked_private_ip"


# --------------------------------------------------------------------------- #
# Async wrapper (offloads the blocking getaddrinfo to the thread pool).
# --------------------------------------------------------------------------- #


async def test_async_wrapper_accepts_public() -> None:
    out = await validate_endpoint_async("https://8.8.8.8", allowlist=_EMPTY, allow_http=False)
    assert out == "https://8.8.8.8"


async def test_async_wrapper_rejects_blocked() -> None:
    with pytest.raises(EndpointValidationError) as exc:
        await validate_endpoint_async("https://10.0.0.9", allowlist=_EMPTY, allow_http=False)
    assert exc.value.reason == "blocked_private_ip"
