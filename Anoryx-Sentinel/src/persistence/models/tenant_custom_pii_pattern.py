"""TenantCustomPiiPattern ORM model (F-028, ADR-0034).

Per-tenant client-defined custom PII regex patterns. One row per pattern per
tenant — e.g. a tenant registers `EMPLOYEE_ID` = `EMP-\\d{6}` so their own
internal identifiers are masked/blocked alongside the built-in F-005 Presidio
entities.

Tenant-scoped under RLS (migration 0034, verbatim NULLIF predicate from
ADR-0005 / migrations 0006/0007/0018/0026/0028/0033). One tenant's custom
patterns are never visible to another tenant's session (R4). No DELETE path —
`is_active=False` soft-disables (mirrors tenant_mcp_servers / webhook_config).

`pattern` is a regex validated at write time by the F-028 pattern validator
(src/data_protection/custom_pii/validator.py) — length-bounded, compile-
checked, and ReDoS-heuristic-linted BEFORE it ever reaches this table
(mirrors tenant_mcp_servers' "SSRF-validated before any write" discipline).

`version` is bumped on every content change to a tenant's pattern set (used by
the hot-reload cache to detect staleness — see loader.py). Matching is done by
a standalone `regex`-module engine with a per-match timeout (ReDoS backstop),
NOT Presidio — so custom patterns work on the slim image without spacy.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base


class TenantCustomPiiPattern(Base):
    """A single tenant-scoped custom PII regex pattern."""

    __tablename__ = "tenant_custom_pii_patterns"

    pattern_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Optional scope. NULL = tenant-wide (all teams / all projects).
    team_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # The entity label surfaced in masks/events, e.g. "EMPLOYEE_ID".
    # Uppercase-normalized at registration; used in the [REDACTED:{name}] marker.
    name: Mapped[str] = mapped_column(String(64), nullable=False)

    # The regex pattern text (validated before write). TEXT — patterns can be
    # longer than a VARCHAR bound is worth pinning; a length cap is enforced in
    # the validator, not the column.
    pattern: Mapped[str] = mapped_column(Text(), nullable=False)

    # Confidence score [0,1] attached to matches (drives severity mapping, same
    # scale as Presidio's per-finding score).
    score: Mapped[float] = mapped_column(Float(), nullable=False, server_default="0.85")

    # Per-pattern action override: "mask" | "tokenize" | "block". NULL = use the
    # tenant/global custom-PII default action.
    action: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Bumped on every content change to this tenant's pattern set (hot-reload
    # staleness signal).
    version: Mapped[int] = mapped_column(Integer(), nullable=False, server_default="1")

    is_active: Mapped[bool] = mapped_column(Boolean(), nullable=False, server_default="true")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("length(name) > 0", name="ck_tenant_custom_pii_name_nonempty"),
        CheckConstraint("length(pattern) > 0", name="ck_tenant_custom_pii_pattern_nonempty"),
        CheckConstraint("score >= 0 AND score <= 1", name="ck_tenant_custom_pii_score_range"),
        Index("ix_tenant_custom_pii_tenant_id", "tenant_id"),
        Index("ix_tenant_custom_pii_tenant_active", "tenant_id", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<TenantCustomPiiPattern pattern_id={self.pattern_id!r} "
            f"tenant={self.tenant_id!r} name={self.name!r} is_active={self.is_active!r}>"
        )
