"""policy_distributions — one row per submitted policy distribution (O-004, ADR-0004).

Tenant-scoped (RLS). Records a distribution Delta submitted: the byte-identical signed
policy record (`signed_record`, kept verbatim so it forwards unchanged and verifies
unchanged on Sentinel), its content_hash, and the aggregate `state` recomputed from the
per-target rows (pending → distributed / partial / failed). policy_type is the SIX-value
locked set (membership only, never widened). App-role reads/writes (UPDATE moves state).
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class PolicyDistribution(Base):
    __tablename__ = "policy_distributions"

    distribution_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # One of the SIX locked policy_type values (membership only — never widened).
    policy_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # pending | distributed | partial | failed (aggregate over the target rows).
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'pending'"))
    # The exact signed policy record — kept verbatim for byte-identical forwarding.
    signed_record: Mapped[dict] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
