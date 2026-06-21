"""BatchFile ORM model (F-015, ADR-0018 §9).

One row per file in a batch. Tenant-scoped (RLS column `tenant_id`, independent of
the parent batch so RLS scopes file rows directly). The row's terminal status IS
the checkpoint (R5/R7): a resumed/redelivered batch skips files already in a
terminal state. `outcome` records the SECURITY decision (allowed/blocked/redacted);
`failure_class` records a DLQ reason class — NEVER raw content / secrets / PII.

RLS (ENABLE+FORCE, NULLIF predicate) + the sentinel_app GRANT live in migration 0018.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base

# Per-file lifecycle. queued/running are transient; the rest are terminal.
FILE_STATUSES = ("queued", "running", "done", "blocked", "dead_lettered")
# Terminal set used by checkpoint/resume + completion detection (R5/R7).
FILE_TERMINAL_STATUSES = ("done", "blocked", "dead_lettered")
# Security outcome (NULL until processed; dead-lettered files have no outcome).
FILE_OUTCOMES = ("allowed", "blocked", "redacted")


class BatchFile(Base):
    """A single file within a batch (one row per object)."""

    __tablename__ = "batch_files"

    file_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    batch_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("batches.batch_id", ondelete="CASCADE"),
        nullable=False,
    )
    # RLS column — matches the parent batch's tenant; scoped independently.
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )

    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="queued")
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # DLQ / failure reason CLASS only (e.g. 'fetch_error'); never raw content.
    failure_class: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # An object appears at most once per batch (file-level dedup).
        UniqueConstraint("batch_id", "object_key", name="uq_batch_files_batch_object"),
        CheckConstraint(
            "status IN ('queued','running','done','blocked','dead_lettered')",
            name="ck_batch_files_status",
        ),
        CheckConstraint(
            "outcome IS NULL OR outcome IN ('allowed','blocked','redacted')",
            name="ck_batch_files_outcome",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_batch_files_attempt_count"),
        Index("ix_batch_files_tenant_id", "tenant_id"),
        Index("ix_batch_files_batch_id", "batch_id"),
        # Manifest + checkpoint queries filter by (batch_id, status).
        Index("ix_batch_files_batch_status", "batch_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<BatchFile file_id={self.file_id!r} status={self.status!r}>"
