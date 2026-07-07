"""Self-hosted ICE/TURN configuration for the 1-on-1 huddle bootstrap (R-007).

Serves ``GET /v1/huddles/ice-servers`` (``contracts/openapi.yaml`` ``IceServersResponse``).
HONESTY BOUNDARY (verbatim, contract): "Rendly never hands out an external meeting link (no
Zoom/Meet URL leaves the org)." This module hands out ONLY self-hosted STUN/TURN endpoints the
operator configures via env — never a third-party URL, never a redirect.

Short-lived TURN credentials use the coturn ``REST API`` time-limited convention (a widely
deployed, non-custom scheme — RFC 5766 TURN + a shared-secret HMAC, NOT a Rendly invention):
``username = "<expiry_unix_ts>:<user_id>"``, ``credential = base64(HMAC-SHA1(secret, username))``.
The TURN server (configured separately, outside this repo — R-010 deployment) validates the same
HMAC, so no per-user credential is ever stored here. If no shared secret is configured, only STUN
entries are returned (``username``/``credential`` null) — a safe, self-hosted-only degrade, never
a fabricated credential.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field

_DEFAULT_TTL_SECONDS = 600


def _split_urls(raw: str) -> list[str]:
    return [u.strip() for u in raw.split(",") if u.strip()]


@dataclass(frozen=True)
class IceServerConfig:
    """Operator-configured self-hosted ICE endpoints. Never a third-party meeting service."""

    stun_urls: tuple[str, ...] = field(default_factory=tuple)
    turn_urls: tuple[str, ...] = field(default_factory=tuple)
    turn_secret: str | None = None
    ttl_seconds: int = _DEFAULT_TTL_SECONDS

    @staticmethod
    def from_env() -> "IceServerConfig":
        """Read ``RENDLY_STUN_URLS`` / ``RENDLY_TURN_URLS`` / ``RENDLY_TURN_SECRET`` /
        ``RENDLY_ICE_TTL_SECONDS`` (all optional; an unset TURN secret degrades to STUN-only)."""
        ttl_raw = os.environ.get("RENDLY_ICE_TTL_SECONDS", "").strip()
        try:
            ttl = int(ttl_raw) if ttl_raw else _DEFAULT_TTL_SECONDS
        except ValueError:
            ttl = _DEFAULT_TTL_SECONDS
        ttl = max(1, min(ttl, 86400))  # matches the contract-locked IceServersResponse bound
        return IceServerConfig(
            stun_urls=tuple(_split_urls(os.environ.get("RENDLY_STUN_URLS", ""))),
            turn_urls=tuple(_split_urls(os.environ.get("RENDLY_TURN_URLS", ""))),
            turn_secret=os.environ.get("RENDLY_TURN_SECRET") or None,
            ttl_seconds=ttl,
        )


def _turn_credential(*, secret: str, username: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def build_ice_servers(config: IceServerConfig, *, user_id: str, now_epoch: int) -> dict:
    """Build the ``IceServersResponse`` body for ``user_id``. Pure (takes the clock explicitly)."""
    servers: list[dict] = []
    if config.stun_urls:
        servers.append({"urls": list(config.stun_urls), "username": None, "credential": None})
    if config.turn_urls and config.turn_secret:
        expiry = now_epoch + config.ttl_seconds
        username = f"{expiry}:{user_id}"
        servers.append(
            {
                "urls": list(config.turn_urls),
                "username": username,
                "credential": _turn_credential(secret=config.turn_secret, username=username),
            }
        )
    return {"ice_servers": servers, "ttl_seconds": config.ttl_seconds}
