"""ProjectRepository — data access for the projects table (F-003b).

F-003b (ADR-0005): get_by_id now accepts caller_tenant_id as a defense-in-depth
guard. RLS on the tenant session is the primary boundary; this check is the second
lock that makes the security intent explicit in code and guards privileged-session
misuse.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.project import Project


class ProjectNotFoundError(Exception):
    """Raised when a project lookup finds no matching row."""


class ProjectRepository:
    """Data-access object for the projects table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        tenant_id: str,
        team_id: str,
        name: str,
        display_name: str | None = None,
    ) -> Project:
        """Create a new project under the given team and tenant."""
        project = Project(
            project_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            team_id=team_id,
            name=name,
            display_name=display_name,
            is_active=True,
        )
        self._session.add(project)
        await self._session.flush()
        return project

    async def get_by_id(
        self, project_id: str, caller_tenant_id: str
    ) -> Project:
        """Return the project for project_id, or raise ProjectNotFoundError.

        caller_tenant_id is REQUIRED (LOW-1, ADR-0005 round-2).  The WHERE
        clause always includes AND tenant_id = caller_tenant_id.  RLS on the
        tenant session is the primary boundary; this check is the second lock.
        """
        stmt = select(Project).where(Project.project_id == project_id)
        stmt = stmt.where(Project.tenant_id == caller_tenant_id)
        result = await self._session.execute(stmt)
        project = result.scalar_one_or_none()
        if project is None:
            raise ProjectNotFoundError(f"Project not found: {project_id!r}")
        return project

    async def list_for_team(
        self,
        team_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Project]:
        """Return active projects for a team, ordered by name.

        Default limit: 100.  Hard max: 1000.  Values <= 0 are rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, 1000)
        stmt = (
            select(Project)
            .where(Project.team_id == team_id, Project.is_active.is_(True))
            .order_by(Project.name)
            .limit(effective_limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def deactivate(
        self, project_id: str, caller_tenant_id: str
    ) -> Project:
        """Soft-delete a project by marking it inactive."""
        project = await self.get_by_id(project_id, caller_tenant_id=caller_tenant_id)
        project.is_active = False
        project.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        return project
