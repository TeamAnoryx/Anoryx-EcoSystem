"""User ORM model (F-003).

Passwords are stored as Argon2id hashes via argon2-cffi. Plaintext passwords
are NEVER stored, logged, or returned. The password_hash column holds the full
Argon2 PHC string (prefix + parameters + salt + digest — all opaque to the DB).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from persistence.models.base import Base


class User(Base):
    """Sentinel admin/operator user. Passwords stored as Argon2id hashes only."""

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    # Argon2id PHC string. Never plaintext. Never logged.
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)

    display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")  # noqa: F821
    role_assignments: Mapped[list["RoleAssignment"]] = relationship(  # noqa: F821
        "RoleAssignment", back_populates="user"
    )

    __table_args__ = (
        Index("ix_users_tenant_id", "tenant_id"),
        Index("ix_users_tenant_email", "tenant_id", "email", unique=True),
    )

    def __repr__(self) -> str:
        # Never include email or password_hash in repr (PII / secret).
        return f"<User user_id={self.user_id!r} tenant_id={self.tenant_id!r}>"
