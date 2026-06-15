"""RoleAssignment ORM model (F-003).

Maps users to roles within a tenant (and optionally narrower scopes: team or project).
Row-level security (RLS) is enabled on the tenants, teams, projects, users,
virtual_api_keys, policies, and policy_versions tables in migration 0002_rbac,
forcing isolation between tenants. This table defines the role each user holds.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from persistence.models.base import Base

# Sentinel RBAC roles — minimal set for MVP.
VALID_ROLES = frozenset({"admin", "operator", "viewer", "auditor"})


class RoleAssignment(Base):
    """Assigns a role to a user, scoped to tenant (and optionally team/project)."""

    __tablename__ = "role_assignments"

    role_assignment_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # NULL = tenant-wide scope; set for team-scoped or project-scoped assignments.
    team_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("teams.team_id", ondelete="CASCADE"),
        nullable=True,
    )
    project_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("projects.project_id", ondelete="CASCADE"),
        nullable=True,
    )

    # Role value — validated against VALID_ROLES in the repository before insert.
    role: Mapped[str] = mapped_column(String(64), nullable=False)

    granted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="role_assignments")  # noqa: F821

    __table_args__ = (
        Index("ix_ra_user_id", "user_id"),
        Index("ix_ra_tenant_id", "tenant_id"),
        Index("ix_ra_tenant_user_role", "tenant_id", "user_id", "role"),
    )

    def __repr__(self) -> str:
        return (
            f"<RoleAssignment user_id={self.user_id!r} "
            f"tenant_id={self.tenant_id!r} role={self.role!r}>"
        )
