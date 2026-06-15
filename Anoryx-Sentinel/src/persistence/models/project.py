"""Project ORM model (F-003).

A project belongs to a team (and transitively to a tenant). Virtual API keys
and events are scoped to projects. project_id is UUID v4 as VARCHAR(64).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from persistence.models.base import Base


class Project(Base):
    """A project within a team, scoping API keys and events."""

    __tablename__ = "projects"

    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    team_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("teams.team_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    team: Mapped["Team"] = relationship("Team", back_populates="projects")  # noqa: F821

    __table_args__ = (
        Index("ix_projects_team_id", "team_id"),
        Index("ix_projects_tenant_id", "tenant_id"),
        Index("ix_projects_team_name", "team_id", "name", unique=True),
    )

    def __repr__(self) -> str:
        return f"<Project project_id={self.project_id!r} team_id={self.team_id!r}>"
