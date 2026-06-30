"""DbRefreshTokenStore — the DB-backed ``RefreshTokenStore`` (R-004).

Implements the R-003 ``RefreshTokenStore`` ABC byte-for-byte (no contract change):

    def issue(self, *, user_id, tenant_id, scopes, roles, ttl_seconds) -> str
    def rotate(self, raw_token, *, ttl_seconds) -> RotationResult
    def revoke(self, raw_token) -> None

ONLY the storage moves to Postgres; the in-memory semantics are reproduced EXACTLY:
  * opaque token = ``"rt_" + secrets.token_urlsafe(32)``; stored at rest as SHA-256 hex
    only (a store dump never yields usable tokens; lookup hashes the presented token).
  * family_id = ``secrets.token_hex(16)``, generation int (0 at issue), used/revoked bools.
  * rotate mints generation+1 in the SAME family, marks the old ``used=True``.
  * REUSE: rotating a token whose record is already ``used`` revokes the WHOLE family and
    raises ``RefreshReuse``. Unknown / expired / revoked-family all raise ``RefreshInvalid``.
    revoke marks the family revoked (idempotent, never raises on unknown).

TENANT RESOLUTION FOR rotate/revoke (the chosen approach for the no-tenant-arg signatures):
``rotate``/``revoke`` receive only the raw token, so the tenant is unknown up front. We do
a NARROW privileged lookup of ``tenant_id`` by ``token_hash`` (the PK) ONLY to discover
which tenant to scope to; every SECURITY decision (family revoked? expired? used?) and
every WRITE is then re-made under ``get_tenant_session(that_tenant)`` so RLS governs the
mutation and the row stays bound to its own tenant. The privileged read makes no security
decision — it just answers "which tenant owns this hash". This works across a FRESH
connection because the state is persisted, not in-process.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from ..auth.refresh import (
    Clock,
    RefreshInvalid,
    RefreshReuse,
    RefreshTokenStore,
    RotationResult,
)
from .database import get_privileged_session, get_tenant_session
from .models import RefreshTokenFamilyRow, RefreshTokenRow

_REFRESH_PREFIX = "rt_"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DbRefreshTokenStore(RefreshTokenStore):
    """A Postgres-backed refresh-token store. Same rotation/reuse semantics as in-memory."""

    def __init__(self, clock: Clock | None = None) -> None:
        # Injectable clock matches the in-memory store (tests freeze/advance time). The ABC
        # methods are unchanged — this constructor is an implementation detail.
        self._clock: Clock = clock or _utc_now

    def _new_token(self) -> str:
        return _REFRESH_PREFIX + secrets.token_urlsafe(32)

    def _expiry(self, ttl_seconds: int) -> datetime:
        return self._clock() + timedelta(seconds=ttl_seconds)

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
        family_id = secrets.token_hex(16)
        now = self._clock()
        with get_tenant_session(tenant_id) as session:
            session.add(
                RefreshTokenFamilyRow(
                    family_id=family_id,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    revoked=False,
                    created_at=now,
                )
            )
            # The family must exist before the token row (FK family_id). autoflush is off,
            # so flush the parent explicitly rather than rely on unit-of-work ordering.
            session.flush()
            session.add(
                RefreshTokenRow(
                    token_hash=_hash_token(raw),
                    family_id=family_id,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    generation=0,
                    used=False,
                    expires_at=self._expiry(ttl_seconds),
                    scopes=sorted(scopes),
                    roles=list(roles),
                    created_at=now,
                )
            )
            session.commit()
        return raw

    def _discover_tenant(self, token_hash: str) -> str | None:
        """Privileged, security-decision-free lookup of the owning tenant by token hash."""
        with get_privileged_session() as session:
            return session.execute(
                select(RefreshTokenRow.tenant_id).where(RefreshTokenRow.token_hash == token_hash)
            ).scalar_one_or_none()

    def rotate(self, raw_token: str, *, ttl_seconds: int) -> RotationResult:
        token_hash = _hash_token(raw_token)
        tenant_id = self._discover_tenant(token_hash)
        if tenant_id is None:
            raise RefreshInvalid("unknown refresh token")

        # One get_tenant_session == one autobegun transaction. The row-lock (SELECT ...
        # FOR UPDATE), the used==False check, and the used=True / family-revoke writes ALL
        # run inside THIS single transaction, so two callers presenting the same raw_token
        # serialise: the second blocks on the lock until the first commits, then observes
        # used==True and is handled as reuse (family revoked). Both can never pass the
        # used==False check. (NOT session.begin() — a sync Session autobegins; an explicit
        # begin() would double-begin, which a broad except could swallow into fail-open;
        # banked rule 6 / Sentinel ADR-0026.)
        with get_tenant_session(tenant_id) as session:
            token = session.execute(
                select(RefreshTokenRow)
                .where(RefreshTokenRow.token_hash == token_hash)
                .with_for_update()
            ).scalar_one_or_none()
            if token is None:
                # RLS hid it (tenant mismatch) — indistinguishable from unknown.
                raise RefreshInvalid("unknown refresh token")
            family = session.execute(
                select(RefreshTokenFamilyRow).where(
                    RefreshTokenFamilyRow.family_id == token.family_id
                )
            ).scalar_one_or_none()

            # Snapshot every field BEFORE any write (expire_on_commit=False, but read first).
            family_id = token.family_id
            generation = token.generation
            user_id = token.user_id
            row_tenant = token.tenant_id
            scopes = frozenset(token.scopes)
            roles = tuple(token.roles)
            expires_at = token.expires_at
            used = token.used
            family_revoked = family.revoked if family is not None else True

            if family is None or family_revoked:
                raise RefreshInvalid("refresh token family revoked")
            if self._clock() >= expires_at:
                raise RefreshInvalid("refresh token expired")
            if used:
                # Replay of a rotated-past token: revoke the WHOLE family (reuse-detection).
                session.execute(
                    update(RefreshTokenFamilyRow)
                    .where(RefreshTokenFamilyRow.family_id == family_id)
                    .values(revoked=True)
                )
                session.commit()
                raise RefreshReuse("refresh token reuse detected; family revoked")

            # Consume the presented token and mint its successor in the same family.
            session.execute(
                update(RefreshTokenRow)
                .where(RefreshTokenRow.token_hash == token_hash)
                .values(used=True)
            )
            successor = self._new_token()
            session.add(
                RefreshTokenRow(
                    token_hash=_hash_token(successor),
                    family_id=family_id,
                    tenant_id=row_tenant,
                    user_id=user_id,
                    generation=generation + 1,
                    used=False,
                    expires_at=self._expiry(ttl_seconds),
                    scopes=sorted(scopes),
                    roles=list(roles),
                    created_at=self._clock(),
                )
            )
            session.commit()

        return RotationResult(
            new_token=successor,
            user_id=user_id,
            tenant_id=row_tenant,
            scopes=scopes,
            roles=roles,
        )

    def revoke(self, raw_token: str) -> None:
        # Idempotent logout: unknown token is a silent no-op (no existence leak, no raise).
        token_hash = _hash_token(raw_token)
        tenant_id = self._discover_tenant(token_hash)
        if tenant_id is None:
            return
        with get_tenant_session(tenant_id) as session:
            family_id = session.execute(
                select(RefreshTokenRow.family_id).where(RefreshTokenRow.token_hash == token_hash)
            ).scalar_one_or_none()
            if family_id is None:
                return
            session.execute(
                update(RefreshTokenFamilyRow)
                .where(RefreshTokenFamilyRow.family_id == family_id)
                .values(revoked=True)
            )
            session.commit()
