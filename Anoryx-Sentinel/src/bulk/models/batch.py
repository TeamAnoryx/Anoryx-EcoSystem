"""Batch ORM model (F-015, ADR-0018 §9).

One row per submitted batch. Tenant-scoped (RLS column `tenant_id`). Idempotency
is enforced by a UNIQUE (tenant_id, idempotency_key) constraint: a replayed key
returns the existing batch — never a second batch (R5 / vector 9).

The four stable IDs of the submitting key are stored so the worker can run each
file under the correct tenant scope + attribute events honestly (ADR-0018 §2/§8).

RLS (ENABLE+FORCE, NULLIF predicate) + the sentinel_app GRANT live in migration
0018 — without them a tenant session cannot touch this new table.
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

# Batch-level lifecycle. queued -> running -> completed. Terminal = completed.
BATCH_STATUSES = ("queued", "running", "completed")


class Batch(Base):
    """A submitted bulk batch (one row per batch_id)."""

    __tablename__ = "batches"

    batch_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # RLS column + the submitting key's four stable IDs (server-resolved at submit).
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)

    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    # Optional target model the files are destined for. When set, F-008 model
    # allow/deny policy is enforced per file (ADR-0018 §5). NULL = detectors-only.
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="queued")
    total_files: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # Idempotency: a (tenant, key) pair maps to exactly one batch (vector 9).
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_batches_tenant_idem"),
        CheckConstraint(
            "status IN ('queued','running','completed')",
            name="ck_batches_status",
        ),
        CheckConstraint("total_files >= 0", name="ck_batches_total_files"),
        Index("ix_batches_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return f"<Batch batch_id={self.batch_id!r} status={self.status!r}>"
