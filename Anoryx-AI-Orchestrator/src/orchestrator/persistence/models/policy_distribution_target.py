"""policy_distribution_targets — per-target independent distribution status (O-004, ADR-0004).

Tenant-scoped (RLS). One row per (distribution, sentinel_id) — UNIQUE so a target is
idempotent within a distribution. Each target carries its OWN state and bounded-retry
bookkeeping (Fork C/D): attempt_count vs max_attempts, last_error, next_attempt_at, and
distributed_at on success. The set of `failed` targets IS the queryable dead-letter set.
App-role reads/writes (UPDATE drives the retry state machine).
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class PolicyDistributionTarget(Base):
    __tablename__ = "policy_distribution_targets"

    target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # FK → policy_distributions(distribution_id) ON DELETE CASCADE (in the migration DDL).
    distribution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sentinel_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # pending | distributed | failed (per-target — independent of the parent aggregate).
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'pending'"))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_attempt_at: Mapped[object | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    distributed_at: Mapped[object | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
