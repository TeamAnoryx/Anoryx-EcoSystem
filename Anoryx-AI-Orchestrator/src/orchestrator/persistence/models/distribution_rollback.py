"""distribution_rollbacks — tamper-evident GLOBAL rollback-correlation chain
(O-014, ADR-0014).

Written by the PRIVILEGED session (mirrors external_gateway_audit_log structurally), and
— because this is genuinely tenant-relevant audit data a tenant could read back — this
table CARRIES RLS: SELECT scoped to the row's own tenant_id, writes privileged-only.
Append-only via BEFORE UPDATE/DELETE deny triggers.

One row per OPERATOR-TRIGGERED rollback action: correlates the NEW distribution created
by the rollback (`new_distribution_id`) with the PRIOR distribution whose signed_record it
byte-identically re-submitted (`source_distribution_id`) and the distribution it
supersedes (`superseded_distribution_id`, the one that was "current" immediately before
this rollback ran). This is a correlation record, NOT a duplicate of
distribution_audit_log — the new distribution's own submission is ALSO independently
chain-audited there (disposition='submitted'), exactly like any other distribution.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class DistributionRollback(Base):
    __tablename__ = "distribution_rollbacks"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_distribution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    superseded_distribution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    new_distribution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
