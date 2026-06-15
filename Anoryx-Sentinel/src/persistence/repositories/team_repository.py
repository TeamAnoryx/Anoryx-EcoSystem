"""TeamRepository — data access for the teams table (F-003).

Tenant isolation enforcement (caller_tenant_id scoping on get_by_id, RLS role
switching) is deferred to F-003b. F-003 ships the schema and repository layer
only; see ADR-0004 for the full scope statement.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.team import Team


class TeamNotFoundError(Exception):
    """Raised when a team lookup finds no matching row."""


class TeamRepository:
    """Data-access object for the teams table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        tenant_id: str,
        name: str,
        display_name: str | None = None,
    ) -> Team:
        """Create a new team under the given tenant."""
        team = Team(
            team_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=name,
            display_name=display_name,
            is_active=True,
        )
        self._session.add(team)
        await self._session.flush()
        return team

    async def get_by_id(self, team_id: str) -> Team:
        """Return the team for team_id, or raise TeamNotFoundError.

        PK lookup only. Tenant scoping is deferred to F-003b.
        """
        stmt = select(Team).where(Team.team_id == team_id)
        result = await self._session.execute(stmt)
        team = result.scalar_one_or_none()
        if team is None:
            raise TeamNotFoundError(f"Team not found: {team_id!r}")
        return team

    async def list_for_tenant(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Team]:
        """Return active teams for a tenant, ordered by name.

        Default limit: 100.  Hard max: 1000.  Values <= 0 are rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, 1000)
        stmt = (
            select(Team)
            .where(Team.tenant_id == tenant_id, Team.is_active.is_(True))
            .order_by(Team.name)
            .limit(effective_limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def deactivate(self, team_id: str) -> Team:
        """Soft-delete a team by marking it inactive."""
        team = await self.get_by_id(team_id)
        team.is_active = False
        team.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        return team
