"""RBAC access-token orchestration (D-017, ADR-0017).

DTO <-> store mapping + token generation/hashing + the role-rank check (a pure
function, no DB — mirrors ``pm.service._would_create_cycle``/
``capacity.service._greedy_rebalance``'s pure-function testability shape). Mirrors
every prior Delta package: store functions never commit, this layer commits once per
mutating call.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from . import store
from .schemas import (
    AccessRole,
    AccessTokenCreateRequest,
    AccessTokenIssuedView,
    AccessTokenRevokeRequest,
    AccessTokenView,
)

_ROLE_RANK: dict[str, int] = {"tenant_auditor": 0, "tenant_admin": 1}

_RAW_TOKEN_BYTES = 32  # secrets.token_urlsafe(32) -> 256 bits of entropy


class TokenNotFoundError(LookupError):
    pass


def role_at_least(actual: str, minimum: str) -> bool:
    """True iff ``actual`` outranks or equals ``minimum`` in the two-role hierarchy
    (`tenant_auditor` < `tenant_admin`). An unrecognized role never satisfies any
    minimum (fail-closed) — mirrors every other honesty/fail-closed check in this
    session."""
    actual_rank = _ROLE_RANK.get(actual)
    minimum_rank = _ROLE_RANK.get(minimum)
    if actual_rank is None or minimum_rank is None:
        return False
    return actual_rank >= minimum_rank


def generate_raw_token() -> str:
    return secrets.token_urlsafe(_RAW_TOKEN_BYTES)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record_to_view(record: store.AccessTokenRecord) -> AccessTokenView:
    return AccessTokenView(
        token_id=record.token_id,
        tenant_id=record.tenant_id,
        name=record.name,
        role=record.role,  # type: ignore[arg-type]
        created_at=record.created_at,
        revoked_at=record.revoked_at,
    )


async def create_token(
    session: AsyncSession, req: AccessTokenCreateRequest
) -> AccessTokenIssuedView:
    raw_token = generate_raw_token()
    record = await store.create_token(
        session,
        tenant_id=req.tenant_id,
        name=req.name,
        role=req.role,
        token_hash=hash_token(raw_token),
        now=_now(),
    )
    await session.commit()
    return AccessTokenIssuedView(
        token_id=record.token_id,
        tenant_id=record.tenant_id,
        name=record.name,
        role=record.role,  # type: ignore[arg-type]
        created_at=record.created_at,
        revoked_at=record.revoked_at,
        token=raw_token,
    )


async def list_token_views(session: AsyncSession, *, limit: int) -> list[AccessTokenView]:
    records = await store.list_tokens(session, limit=limit)
    return [_record_to_view(r) for r in records]


async def revoke_token(
    session: AsyncSession, *, token_id: str, req: AccessTokenRevokeRequest
) -> AccessTokenView:
    existing = await store.get_token(session, token_id=token_id)
    if existing is None:
        raise TokenNotFoundError(token_id)
    now = _now()
    await store.revoke_token(session, token_id=token_id, now=now)
    record = await store.get_token(session, token_id=token_id)
    await session.commit()
    if record is None:
        raise TokenNotFoundError(token_id)  # unreachable: just wrote it in this transaction
    return _record_to_view(record)


async def resolve_role_from_bearer(
    session: AsyncSession, *, bearer_token: str
) -> AccessRole | None:
    """Used only by ``rbac.auth.require_role``. Looks up the presented bearer's role
    by its hash within the caller's already-tenant-scoped session — returns `None`
    for an unknown, revoked, or (structurally, by RLS) wrong-tenant token."""
    record = await store.get_active_token_by_hash(session, token_hash=hash_token(bearer_token))
    return None if record is None else record.role  # type: ignore[return-value]
