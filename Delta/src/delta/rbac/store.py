"""RBAC access-token persistence (D-017, ADR-0017).

Tenant-scoped reads/writes against ``access_tokens`` (migration 0011). Every function
takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like every prior Delta package.

Only ``token_hash`` (SHA-256 hex digest) is ever read or written here — the raw token
value never touches this module beyond being hashed once at generation time in
``service.py``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import access_tokens

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class AccessTokenRecord:
    token_id: str
    tenant_id: str
    name: str
    role: str
    created_at: datetime
    revoked_at: datetime | None


def _record_from_row(row) -> AccessTokenRecord:
    return AccessTokenRecord(
        token_id=row.token_id,
        tenant_id=row.tenant_id,
        name=row.name,
        role=row.role,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
    )


async def create_token(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    role: str,
    token_hash: str,
    now: datetime,
    token_id: str | None = None,
) -> AccessTokenRecord:
    tid = token_id or str(uuid.uuid4())
    await session.execute(
        insert(access_tokens).values(
            token_id=tid,
            tenant_id=tenant_id,
            name=name,
            role=role,
            token_hash=token_hash,
            created_at=now,
            revoked_at=None,
        )
    )
    return AccessTokenRecord(
        token_id=tid, tenant_id=tenant_id, name=name, role=role, created_at=now, revoked_at=None
    )


async def get_token(session: AsyncSession, *, token_id: str) -> AccessTokenRecord | None:
    row = (
        await session.execute(select(access_tokens).where(access_tokens.c.token_id == token_id))
    ).first()
    return None if row is None else _record_from_row(row)


async def list_tokens(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[AccessTokenRecord]:
    stmt = (
        select(access_tokens).order_by(access_tokens.c.created_at.desc()).limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_record_from_row(r) for r in rows]


async def revoke_token(session: AsyncSession, *, token_id: str, now: datetime) -> None:
    await session.execute(
        update(access_tokens).where(access_tokens.c.token_id == token_id).values(revoked_at=now)
    )


async def get_active_token_by_hash(
    session: AsyncSession, *, token_hash: str
) -> AccessTokenRecord | None:
    """Used only by ``rbac.auth.require_role`` — looks up a presented token's role by
    its hash, scoped to the caller's already-RLS-selected tenant session (a token that
    does not belong to that tenant is invisible here, not a separate check). Excludes
    revoked tokens at the SQL layer, not just by the caller checking the field."""
    stmt = select(access_tokens).where(
        (access_tokens.c.token_hash == token_hash) & (access_tokens.c.revoked_at.is_(None))
    )
    row = (await session.execute(stmt)).first()
    return None if row is None else _record_from_row(row)
