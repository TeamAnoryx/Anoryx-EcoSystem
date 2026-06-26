"""Refresh-token store — rotation, reuse-detection, revocation (R-003 FORK B+E).

The contract's refresh token is an OPAQUE handle (``rt_<...>``, not a JWT) and mandates
"rotate on each refresh", which implies server-side state — exactly what reuse-detection and
``/auth/revoke`` need. This module is that state behind a narrow :class:`RefreshTokenStore` seam;
R-004 implements it against the database with no contract change.

Security model:
  * **Hashed at rest.** Only the SHA-256 of each opaque token is stored, so a store dump never
    yields usable tokens. Lookup hashes the presented token.
  * **Rotation.** Each refresh consumes the presented token (marks it used) and issues a fresh
    token in the same *family* at the next generation.
  * **Reuse-detection.** Presenting an already-used token means it was replayed (the legitimate
    client already rotated past it) — the ENTIRE family is revoked, so a stolen-then-replayed
    token also burns the thief's freshly-minted one. Reuse and unknown/expired both surface to the
    client as the same generic 401 (no oracle).
  * **Revocation (logout).** ``/auth/revoke`` revokes the presented token's whole family.
    Idempotent: an unknown/already-revoked token is a silent no-op (no token-existence leak).
"""

from __future__ import annotations

import abc
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

_REFRESH_PREFIX = "rt_"

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class RefreshError(Exception):
    """Base for refresh failures; both subclasses surface as 401 invalid_token."""


class RefreshInvalid(RefreshError):
    """The refresh token is unknown, expired, or belongs to a revoked family."""


class RefreshReuse(RefreshError):
    """An already-used refresh token was replayed; its family has now been revoked."""


@dataclass(frozen=True)
class RotationResult:
    """The product of a successful rotation: a new token + the re-issuance inputs."""

    new_token: str
    user_id: str
    tenant_id: str
    scopes: frozenset[str]
    roles: tuple[str, ...]


@dataclass
class _Record:
    family_id: str
    generation: int
    user_id: str
    tenant_id: str
    scopes: frozenset[str]
    roles: tuple[str, ...]
    expires_at: datetime
    used: bool = False


class RefreshTokenStore(abc.ABC):
    """The refresh-token state seam. R-004 implements this against the database."""

    @abc.abstractmethod
    def issue(
        self,
        *,
        user_id: str,
        tenant_id: str,
        scopes: frozenset[str],
        roles: tuple[str, ...],
        ttl_seconds: int,
    ) -> str:
        """Mint a NEW refresh-token family (generation 0); return the opaque token."""

    @abc.abstractmethod
    def rotate(self, raw_token: str, *, ttl_seconds: int) -> RotationResult:
        """Consume ``raw_token`` and issue its successor, or raise on invalid/reuse."""

    @abc.abstractmethod
    def revoke(self, raw_token: str) -> None:
        """Revoke the token's whole family (logout). Idempotent; never raises on unknown."""


class InMemoryRefreshTokenStore(RefreshTokenStore):
    """In-memory refresh state. Per-process, lost on restart — the documented R-004 seam."""

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or _utc_now
        self._by_hash: dict[str, _Record] = {}
        self._revoked_families: set[str] = set()

    def _new_token(self) -> str:
        return _REFRESH_PREFIX + secrets.token_urlsafe(32)

    def issue(
        self,
        *,
        user_id: str,
        tenant_id: str,
        scopes: frozenset[str],
        roles: tuple[str, ...],
        ttl_seconds: int,
    ) -> str:
        raw = self._new_token()
        self._by_hash[_hash_token(raw)] = _Record(
            family_id=secrets.token_hex(16),
            generation=0,
            user_id=user_id,
            tenant_id=tenant_id,
            scopes=scopes,
            roles=roles,
            expires_at=self._expiry(ttl_seconds),
        )
        return raw

    def rotate(self, raw_token: str, *, ttl_seconds: int) -> RotationResult:
        record = self._by_hash.get(_hash_token(raw_token))
        if record is None or record.family_id in self._revoked_families:
            raise RefreshInvalid("unknown or revoked refresh token")
        if self._clock() >= record.expires_at:
            raise RefreshInvalid("refresh token expired")
        if record.used:
            # Replay of a rotated-past token: revoke the whole family (reuse-detection).
            self._revoked_families.add(record.family_id)
            raise RefreshReuse("refresh token reuse detected; family revoked")

        record.used = True
        successor = self._new_token()
        self._by_hash[_hash_token(successor)] = _Record(
            family_id=record.family_id,
            generation=record.generation + 1,
            user_id=record.user_id,
            tenant_id=record.tenant_id,
            scopes=record.scopes,
            roles=record.roles,
            expires_at=self._expiry(ttl_seconds),
        )
        return RotationResult(
            new_token=successor,
            user_id=record.user_id,
            tenant_id=record.tenant_id,
            scopes=record.scopes,
            roles=record.roles,
        )

    def revoke(self, raw_token: str) -> None:
        record = self._by_hash.get(_hash_token(raw_token))
        if record is not None:
            self._revoked_families.add(record.family_id)

    def _expiry(self, ttl_seconds: int) -> datetime:
        from datetime import timedelta

        return self._clock() + timedelta(seconds=ttl_seconds)
