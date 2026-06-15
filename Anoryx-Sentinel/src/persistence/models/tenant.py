"""Tenant ORM model (F-003).

A tenant is the top-level organizational unit in Sentinel. All other entities
(teams, projects, agents, users, keys, policies, events) belong to a tenant.
tenant_id is a UUID v4 stored as VARCHAR(64) per contracts/ids.md.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from persistence.models.base import Base


class Tenant(Base):
    """Top-level organizational unit. Scopes all Sentinel resources."""

    __tablename__ = "tenants"

    # Primary key: UUID v4 as VARCHAR(64) (matches contracts/ids.md maxLength 64).
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)

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

    # Relationships (back-populated from child tables).
    teams: Mapped[list["Team"]] = relationship("Team", back_populates="tenant")  # noqa: F821
    users: Mapped[list["User"]] = relationship("User", back_populates="tenant")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Tenant tenant_id={self.tenant_id!r} name={self.name!r}>"
