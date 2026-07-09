"""TenantCustomPiiPatternRepository — data access for the
tenant_custom_pii_patterns table (F-028, ADR-0034, migration 0034).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.tenant_custom_pii_pattern import TenantCustomPiiPattern


class TenantCustomPiiPatternNotFoundError(Exception):
    """Raised when a pattern lookup finds no matching row."""


class TenantCustomPiiPatternRepository:
    """Data-access object for the tenant_custom_pii_patterns table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        tenant_id: str,
        name: str,
        pattern: str,
        *,
        score: float = 0.85,
        action: str | None = None,
        team_id: str | None = None,
        project_id: str | None = None,
    ) -> TenantCustomPiiPattern:
        """Persist a new custom PII pattern. Caller MUST have already validated
        `pattern` via data_protection.custom_pii.validator (mirrors
        TenantMcpServerRepository's "guard BEFORE persistence" discipline — this
        repository does not itself compile/lint the regex)."""
        row = TenantCustomPiiPattern(
            pattern_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            name=name,
            pattern=pattern,
            score=score,
            action=action,
            version=1,
            is_active=True,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def get_by_id(self, pattern_id: str, caller_tenant_id: str) -> TenantCustomPiiPattern:
        """Return the pattern for pattern_id, or raise NotFound.

        caller_tenant_id is REQUIRED (defense-in-depth guard, ADR-0005 round-2).
        """
        stmt = select(TenantCustomPiiPattern).where(
            TenantCustomPiiPattern.pattern_id == pattern_id,
            TenantCustomPiiPattern.tenant_id == caller_tenant_id,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise TenantCustomPiiPatternNotFoundError(
                f"custom PII pattern not found: {pattern_id!r}"
            )
        return row

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        active_only: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TenantCustomPiiPattern]:
        """Return patterns for a tenant, ordered by name. Default: active only.

        Default limit: 100. Hard max: 1000. Values <= 0 are rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, 1000)
        stmt = select(TenantCustomPiiPattern).where(TenantCustomPiiPattern.tenant_id == tenant_id)
        if active_only:
            stmt = stmt.where(TenantCustomPiiPattern.is_active.is_(True))
        stmt = stmt.order_by(TenantCustomPiiPattern.name).limit(effective_limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_active_for_tenant(self, tenant_id: str) -> int:
        """Return the number of active patterns a tenant has (enforce the
        per-tenant cap before registering another — a security control, not
        just a UX limit: an unbounded pattern set is an unbounded per-request
        matching cost)."""
        stmt = select(TenantCustomPiiPattern.pattern_id).where(
            TenantCustomPiiPattern.tenant_id == tenant_id,
            TenantCustomPiiPattern.is_active.is_(True),
        )
        result = await self._session.execute(stmt)
        return len(list(result.scalars().all()))

    async def deactivate(self, pattern_id: str, caller_tenant_id: str) -> TenantCustomPiiPattern:
        """Soft-delete a pattern by marking it inactive and bumping version."""
        row = await self.get_by_id(pattern_id, caller_tenant_id=caller_tenant_id)
        row.is_active = False
        row.version = row.version + 1
        row.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        return row
