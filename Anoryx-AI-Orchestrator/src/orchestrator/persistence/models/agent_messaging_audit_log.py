"""agent_messaging_audit_log — tamper-evident GLOBAL agent-mailbox audit chain (O-012).

Written by the PRIVILEGED session (mirrors relay_audit_log / identity_audit_log
structurally), but — like automation_executions — this table CARRIES RLS: it is
genuinely tenant-relevant audit data a tenant could read back, so SELECT is RLS-scoped
to the row's own tenant_id while writes remain privileged-only. Append-only via BEFORE
UPDATE/DELETE deny triggers.

Records every send ATTEMPT — both a fresh 'sent' and a deduped resend both get a chain
link — matching O-003's ingest-pipeline "was a send attempt durably processed" semantics,
NOT O-011's automation_executions "did an action actually fire" semantics. The
meaningful audited unit here is "was a send attempt durably processed" (ADR-0011 Fork I
made the OPPOSITE choice for its own domain, for its own stated reason; ADR-0012 explains
why THIS domain follows O-003's fresh-accept-or-deduped precedent instead).
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class AgentMessagingAuditLog(Base):
    __tablename__ = "agent_messaging_audit_log"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sender_agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    message_type: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    # sent | deduped
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
