"""Offline mirror configuration validation (F-036, ADR-0041).

An air-gapped deployment must install packages and pull images ONLY from internal
mirrors — never a public internet host. A single overlooked `pypi.org` fallback
silently defeats the air gap. This module validates a deployment's mirror config
so that leak is caught before rollout.

`validate_mirror_config(cfg)` inspects pip index / container-registry hosts and
raises `MirrorConfigError` if ANY of them is a public-internet host. It is a
CONFIG LINT — it does not run a mirror or reach the network; it only reasons about
the hostnames in the config. Fail-closed: an unparseable URL or an unknown/public
host is rejected, not waved through.

"Internal" = an RFC-1918 / loopback / link-local IP, OR a hostname whose suffix is
in the deployment's `internal_suffixes` allow-list (e.g. `.internal`, `.svc`,
`mirror.corp.example`). Everything else — and every KNOWN public index/registry —
is rejected.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

# Well-known public hosts that must NEVER appear in an air-gapped config.
_KNOWN_PUBLIC_HOSTS = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "ghcr.io",
        "docker.io",
        "registry-1.docker.io",
        "index.docker.io",
        "quay.io",
        "gcr.io",
        "public.ecr.aws",
        "registry.npmjs.org",
    }
)


class MirrorConfigError(Exception):
    """A mirror configuration references a public / non-internal host (fail-closed)."""


def _host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
    host = parsed.hostname
    if not host:
        raise MirrorConfigError(f"could not parse a host from mirror URL: {url!r}")
    return host.lower()


def is_internal_host(host: str, internal_suffixes: tuple[str, ...]) -> bool:
    """True if `host` is a private IP or matches an allowed internal suffix."""
    host = host.lower()
    if host in _KNOWN_PUBLIC_HOSTS:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return ip.is_private or ip.is_loopback or ip.is_link_local
    if host in ("localhost",):
        return True
    return any(
        host == s.lstrip(".") or host.endswith(s if s.startswith(".") else f".{s}")
        for s in internal_suffixes
    )


def validate_mirror_config(cfg: dict[str, Any]) -> list[str]:
    """Validate a mirror config; return the list of internal hosts it references.

    `cfg` shape (all optional, at least one required):
      {
        "internal_suffixes": [".internal", ".svc", "mirror.corp.example"],
        "pip_index_url": "https://mirror.corp.example/simple",
        "pip_extra_index_urls": ["https://mirror.corp.example/extra"],
        "container_registries": ["registry.internal:5000"],
      }
    Raises MirrorConfigError on the first public/non-internal host.
    """
    suffixes = tuple(cfg.get("internal_suffixes", []))
    urls: list[str] = []
    if cfg.get("pip_index_url"):
        urls.append(cfg["pip_index_url"])
    urls.extend(cfg.get("pip_extra_index_urls", []) or [])
    urls.extend(cfg.get("container_registries", []) or [])
    if not urls:
        raise MirrorConfigError("mirror config references no pip index or container registry")

    hosts: list[str] = []
    for url in urls:
        host = _host_of(url)
        if not is_internal_host(host, suffixes):
            raise MirrorConfigError(
                f"mirror host {host!r} is not internal — an air-gapped install must not "
                f"reach public hosts (add it to internal_suffixes only if it is a private mirror)"
            )
        hosts.append(host)
    return hosts
