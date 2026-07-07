"""Self-hosted ICE/TURN configuration for 1-on-1 huddles (R-007) — ``GET /v1/huddles/ice-servers``.

Rendly never hands out an external meeting link (no Zoom/Meet URL leaves the org — see
``contracts/openapi.yaml`` honesty boundary #1); this module's job is narrower and purely
technical: give the two peers' browsers the NAT-traversal hints (STUN/TURN server URLs) they
need to negotiate the P2P WebRTC media path directly with each other. It never proxies, stores,
or inspects the media itself (R-001 D4).

CREDENTIAL SCHEME: short-lived TURN credentials via the widely-deployed coturn
"REST API" / RFC 5766 static-auth-secret convention — ``username = "<expiry-unix-ts>:<user_id>"``,
``credential = base64(HMAC-SHA1(shared_secret, username))``. This lets a self-hosted coturn
verify the credential itself with NO shared database / RPC back to Rendly, and the credential
expires (``ttl_seconds``) without Rendly ever needing to revoke it. The shared secret is an
env-injected deploy-time secret (mirrors ``RENDLY_JWT_PRIVATE_KEY_PEM``, R-003 ADR-0003) and is
NEVER logged.

SELF-HOSTED ONLY (honesty boundary, verbatim): this module never falls back to a third-party
public STUN/TURN service (e.g. Google's `stun.l.google.com`) — "data never leaves" extends to NAT
traversal hints, not just message content. If no self-hosted server is configured (``RENDLY_
STUN_URLS``/``RENDLY_TURN_URLS`` both unset), the provider returns an EMPTY ``ice_servers`` list
rather than reaching out to a third party — WebRTC can still attempt a direct/host-candidate
connection between two publicly reachable peers without any ICE server, so this degrades rather
than blocks.

This is R-007's OWN capability, not a documented seam awaiting a later task (unlike the R-008
inspection seam or the D-016 resolver seam) — there is no future task in the roadmap that swaps
this implementation out.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

TURN_SHARED_SECRET_ENV = "RENDLY_TURN_SHARED_SECRET"
STUN_URLS_ENV = "RENDLY_STUN_URLS"
TURN_URLS_ENV = "RENDLY_TURN_URLS"

DEFAULT_TTL_SECONDS = 600
_MAX_URLS_PER_ENTRY = 8
_MAX_ENTRIES = 16


@dataclass(frozen=True)
class IceServerEntry:
    """One ``RTCIceServer`` shape (``IceServersResponse.ice_servers[]``, closed + bounded)."""

    urls: tuple[str, ...]
    username: str | None = None
    credential: str | None = None


@dataclass(frozen=True)
class IceServersConfig:
    ice_servers: tuple[IceServerEntry, ...] = field(default_factory=tuple)
    ttl_seconds: int = DEFAULT_TTL_SECONDS


class IceCredentialProvider(ABC):
    """The ICE/TURN config seam. Async so a future KMS-backed impl can call out without blocking."""

    @abstractmethod
    async def get_ice_servers(self, *, tenant_id: str, user_id: str) -> IceServersConfig:
        raise NotImplementedError


def _split_urls(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [u.strip() for u in raw.split(",") if u.strip()][:_MAX_URLS_PER_ENTRY]


def _turn_credential(*, shared_secret: str, username: str) -> str:
    """RFC 5766 / coturn REST-API TURN credential: base64(HMAC-SHA1(secret, username))."""
    digest = hmac.new(shared_secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1)
    return base64.b64encode(digest.digest()).decode("ascii")


class EnvIceCredentialProvider(IceCredentialProvider):
    """R-007 default: self-hosted STUN (no credential) + optional time-limited TURN credentials.

    Reads server URLs from ``RENDLY_STUN_URLS`` / ``RENDLY_TURN_URLS`` (comma-separated) and, if
    ``RENDLY_TURN_SHARED_SECRET`` is set, mints a short-lived per-user TURN credential for the
    TURN entry. STUN needs no credential (it never relays traffic, so there is nothing to
    authorize). Nothing configured -> an empty ``ice_servers`` list (never a third-party
    fallback, never a hard failure — huddles remain usable, just without NAT-traversal help).
    """

    def __init__(self, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds

    async def get_ice_servers(self, *, tenant_id: str, user_id: str) -> IceServersConfig:
        entries: list[IceServerEntry] = []
        stun_urls = _split_urls(os.environ.get(STUN_URLS_ENV))
        if stun_urls:
            entries.append(IceServerEntry(urls=tuple(stun_urls)))

        turn_urls = _split_urls(os.environ.get(TURN_URLS_ENV))
        if turn_urls:
            shared_secret = os.environ.get(TURN_SHARED_SECRET_ENV)
            if shared_secret:
                # user_id is an opaque UUID surrogate (never PII, ADR-0001 D6) — safe to embed
                # in a credential username that a self-hosted coturn can verify independently.
                expiry = int(time.time()) + self._ttl_seconds
                username = f"{expiry}:{user_id}"
                credential = _turn_credential(shared_secret=shared_secret, username=username)
                entries.append(
                    IceServerEntry(urls=tuple(turn_urls), username=username, credential=credential)
                )
            # TURN URLs configured with NO shared secret -> the entry is dropped (fail-closed):
            # an unauthenticated TURN relay would let anyone tunnel arbitrary traffic through it.

        entries = entries[:_MAX_ENTRIES]
        return IceServersConfig(ice_servers=tuple(entries), ttl_seconds=self._ttl_seconds)
