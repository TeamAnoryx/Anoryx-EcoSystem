"""Team ORM model (F-003).

A team belongs to a tenant. Projects and virtual API keys are scoped to teams.
team_id is UUID v4 as VARCHAR(64) per contracts/ids.md.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from persistence.models.base import Base


class Team(Base):
    """Organizational team within a tenant."""

    __tablename__ = "teams"

    team_id: Mapped[str] = mapped_column(String(64), primary_key=True)
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
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="teams")  # noqa: F821
    projects: Mapped[list["Project"]] = relationship("Project", back_populates="team")  # noqa: F821

    __table_args__ = (
        Index("ix_teams_tenant_id", "tenant_id"),
        Index("ix_teams_tenant_name", "tenant_id", "name", unique=True),
    )

    def __repr__(self) -> str:
        return f"<Team team_id={self.team_id!r} tenant_id={self.tenant_id!r}>"
