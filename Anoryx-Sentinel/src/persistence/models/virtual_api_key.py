"""VirtualApiKey ORM model (F-003).

SECURITY: Plaintext API keys are NEVER stored. Only the HMAC-SHA256 of the
key (under a server secret from the environment) is persisted as key_fingerprint.
Auth compares HMACs using hmac.compare_digest (constant-time) — not plaintext.

The row is the authoritative source of tenant/team/project/agent IDs.
Auth resolves IDs from this row, NEVER trusts client-supplied headers.
This mirrors the F-001 lesson: server-side ID resolution is non-negotiable.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base


class VirtualApiKey(Base):
    """Virtual API key for Sentinel gateway authentication.

    key_fingerprint = HMAC-SHA256(plaintext_key, SENTINEL_KEY_SECRET).
    The four stable IDs (tenant/team/project/agent) are authoritative on this row.
    """

    __tablename__ = "virtual_api_keys"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # HMAC-SHA256 hex digest of the plaintext key.
    # The plaintext key is generated once, shown to the user once, then discarded.
    # Stored as 64-char hex string (SHA-256 = 32 bytes = 64 hex chars).
    key_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Four stable IDs — authoritative source (server-resolved, not client-supplied).
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    team_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("teams.team_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("projects.project_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    # agent_id: lowercase slug, VARCHAR(64). Not FK to agents table
    # because the agent row might not exist at key-creation time in all deployments.
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Human-readable label for the key (never the key value).
    label: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_vak_key_fingerprint", "key_fingerprint", unique=True),
        Index("ix_vak_tenant_id", "tenant_id"),
        Index("ix_vak_project_id", "project_id"),
    )

    def __repr__(self) -> str:
        # Never include key_fingerprint in repr — treat it as semi-sensitive.
        return f"<VirtualApiKey key_id={self.key_id!r} tenant_id={self.tenant_id!r}>"
