"""automation_executions — tamper-evident GLOBAL automation-rule execution chain (O-011).

A single hash chain across every automation-rule execution ATTEMPT (a matched rule that
was actually acted on — 'executed' or 'failed'). A rule that did NOT match produces no
row (there is nothing tamper-evident to say about a rule that did not fire). Written by
the PRIVILEGED session, mirroring relay_audit_log / identity_audit_log structurally, but
UNLIKE those two chains this table carries RLS: it is genuinely tenant-relevant audit
data a tenant can read back (GET /v1/automation/executions), so SELECT is RLS-scoped to
the row's own tenant_id (mirrors ingest_audit_log / distribution_audit_log's `_select` +
`_insert` + deny-update/delete policy shape, 0001/0002) while writes remain
privileged-only. Append-only via BEFORE UPDATE/DELETE deny triggers.

UNIQUE(rule_id, triggering_event_id) is the idempotency dedup gate: if the ingest
background task is ever scheduled twice for the same accepted event (retry, duplicate
dispatch), the second attempt's INSERT hits this constraint and the caller treats it as
"already executed, skip" (a narrow IntegrityError catch, mirroring the ingest pipeline's
own dedup discipline).
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class AutomationExecution(Base):
    __tablename__ = "automation_executions"
    __table_args__ = (
        UniqueConstraint("rule_id", "triggering_event_id", name="uq_ae_rule_triggering_event"),
    )

    # Monotonic bigserial PK — defines chain order.
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    triggering_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # executed | failed
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # opt-in-when-present (hashed iff not None). Short code only (e.g.
    # "distribution_not_found") — never content, never the payload.
    error_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
