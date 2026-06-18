"""TenantRoutingPolicy ORM model (F-006, ADR-0008 §4).

One routing policy row per tenant (PK = tenant_id). Sentinel-LOCAL operational
config — NOT signed Delta policy (which lives in `policies`, signature-gated and
F-008 crypto-verified). When Delta later wants to CONSTRAIN routing it uses the
existing model_allowlist / budget_limit policy types; this table is the
tenant-tunable router config.

allowed_providers is a CSV subset of {openai,anthropic,bedrock}; fallback_order
is an ordered CSV that MUST be a permutation-subset of allowed_providers — the
subset relationship is validated in the repository (a Postgres CHECK cannot
easily express CSV-subset). A CHECK enforces allowed_providers non-empty.

cost_ceiling_cents is an optional per-request CLIENT-SIDE COST-ESTIMATE ceiling
(NULL = no ceiling). It is an estimate, never an authoritative bill.

RLS (ENABLE+FORCE, NULLIF predicate) + a GRANT to sentinel_app are applied in
migration 0007 — without them a tenant session cannot read this NEW table.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base


class TenantRoutingPolicy(Base):
    """Per-tenant multi-provider routing configuration (one row per tenant)."""

    __tablename__ = "tenant_routing_policy"

    # PK = tenant_id (one row per tenant), FK -> tenants with RESTRICT.
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        primary_key=True,
    )

    # Four stable IDs (carried for join symmetry with other tenant tables).
    team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # CSV subset of {openai,anthropic,bedrock}; CHECK non-empty; app validates membership.
    allowed_providers: Mapped[str] = mapped_column(String(64), nullable=False)
    # Ordered CSV; MUST be a permutation-subset of allowed_providers (app-validated).
    fallback_order: Mapped[str] = mapped_column(String(128), nullable=False)
    # Optional per-request client-side cost-estimate ceiling; NULL = no ceiling.
    cost_ceiling_cents: Mapped[float | None] = mapped_column(
        Numeric(precision=20, scale=6), nullable=True
    )

    # F-007 (ADR-0010 §6/§7): classifier preset for the LLM-as-judge step.
    # NULL = unconfigured (the detector uses regex only). Restricted to the two
    # contract presets by ck_trp_classifier_model_id.
    classifier_model_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Audit privacy mode for ML classification events (R10). 'full' | 'redacted'.
    audit_mode: Mapped[str] = mapped_column(String(16), nullable=False, server_default="full")

    # F-009 (ADR-0011 §4/§8): optional per-team RPM ceiling for the three-tier
    # rate limiter. NULL = team tier disabled (default behavior = F-004 key+tenant
    # enforcement, byte-identical). Must be > 0 when set (0 would silently block
    # all team traffic). R7 deviation: Affu-authorized nullable column on existing
    # table; no new table; fully reversible in downgrade().
    team_rpm_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)

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

    __table_args__ = (
        CheckConstraint(
            "length(trim(allowed_providers)) > 0",
            name="ck_trp_allowed_providers_nonempty",
        ),
        # F-007 (ADR-0010 §7): audit_mode enum + classifier preset allow-list.
        CheckConstraint(
            "audit_mode IN ('full','redacted')",
            name="ck_trp_audit_mode",
        ),
        CheckConstraint(
            "classifier_model_id IS NULL OR classifier_model_id IN "
            "('anthropic:claude-haiku-4-5','openai:gpt-4o-mini')",
            name="ck_trp_classifier_model_id",
        ),
        # F-009 (ADR-0011 §4/§8): team_rpm_limit must be positive when set.
        CheckConstraint(
            "team_rpm_limit IS NULL OR team_rpm_limit > 0",
            name="ck_trp_team_rpm_limit",
        ),
        Index("ix_trp_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<TenantRoutingPolicy tenant_id={self.tenant_id!r} "
            f"allowed={self.allowed_providers!r}>"
        )
