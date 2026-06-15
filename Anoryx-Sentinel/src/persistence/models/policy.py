"""Policy and PolicyVersion ORM models (F-003).

Policies flow DOWN from Delta/Orchestrator into Sentinel. Two tables:
- policies: current (latest) policy state for fast lookup.
- policy_versions: full history of every version ever received (append-only).

MONOTONICITY: policy_version is monotonically increasing per policy_id.
Any attempt to insert a version <= the current max version for that policy_id
is rejected by the repository (PolicyMonotonicityError). This is also enforced
by a Postgres trigger in migration 0004.

SIGNATURE: The compact-JWS signature column is stored as-is for format evidence.
Cryptographic verification of the signature is deferred to F-008.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base

# Compact-JWS pattern: three dot-separated base64url segments.
# DDL check: minLength 16, maxLength 4096, format validated in repo + Pydantic.
_SIGNATURE_MAX = 4096


class Policy(Base):
    """Current (latest) policy record. One row per policy_id.

    For full history, query policy_versions. This table supports O(1) lookup
    of the active policy without scanning all versions.
    """

    __tablename__ = "policies"

    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # policy_type discriminator: "budget_limit" | "model_allowlist" | "model_denylist"
    policy_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Four stable IDs — server-side cross-check only (F-008 resolves authoritative scope).
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Monotonic version counter (per policy_id). Updated as new versions arrive.
    current_version: Mapped[int] = mapped_column(BigInteger, nullable=False)

    effective_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Compact-JWS signature — presence+format enforced; crypto-verify in F-008.
    signature: Mapped[str] = mapped_column(String(_SIGNATURE_MAX), nullable=False)

    # Policy-type-specific payload stored as the full JSON text.
    # This is NOT a required-field catch-all; it carries the variant-specific
    # optional fields (period, scope, allowed_model_ids, etc.) that are not
    # stable columns because they differ per variant.
    policy_payload: Mapped[str] = mapped_column(Text, nullable=False)

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
            "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist')",
            name="ck_policies_policy_type",
        ),
        CheckConstraint(
            "current_version >= 1",
            name="ck_policies_version_positive",
        ),
        CheckConstraint(
            f"length(signature) >= 16 AND length(signature) <= {_SIGNATURE_MAX}",
            name="ck_policies_signature_length",
        ),
        Index("ix_policies_tenant_id", "tenant_id"),
        Index("ix_policies_tenant_type", "tenant_id", "policy_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<Policy policy_id={self.policy_id!r} "
            f"type={self.policy_type!r} v={self.current_version}>"
        )


class PolicyVersion(Base):
    """Full history of every policy version ever received. Append-only.

    (policy_id, policy_version) is unique. policy_version is monotonically
    increasing per policy_id — enforced in the repository and by a DB trigger.
    """

    __tablename__ = "policy_versions"

    # Surrogate PK for this history row.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    policy_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("policies.policy_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    policy_version: Mapped[int] = mapped_column(BigInteger, nullable=False)

    policy_type: Mapped[str] = mapped_column(String(64), nullable=False)

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)

    effective_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    signature: Mapped[str] = mapped_column(String(_SIGNATURE_MAX), nullable=False)
    policy_payload: Mapped[str] = mapped_column(Text, nullable=False)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint("policy_id", "policy_version", name="uq_policy_versions_id_ver"),
        CheckConstraint("policy_version >= 1", name="ck_pv_version_positive"),
        CheckConstraint(
            "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist')",
            name="ck_pv_policy_type",
        ),
        CheckConstraint(
            f"length(signature) >= 16 AND length(signature) <= {_SIGNATURE_MAX}",
            name="ck_pv_signature_length",
        ),
        Index("ix_pv_policy_id", "policy_id"),
        Index("ix_pv_policy_id_version", "policy_id", "policy_version"),
        Index("ix_pv_tenant_id", "tenant_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<PolicyVersion policy_id={self.policy_id!r} "
            f"v={self.policy_version}>"
        )
