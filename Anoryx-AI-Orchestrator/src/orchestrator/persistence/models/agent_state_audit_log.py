"""agent_state_audit_log — tamper-evident GLOBAL shared-state audit chain (O-012).

Mirrors O-011's automation_executions "only the meaningful outcome" semantics, NOT
O-003/agent_messaging_audit_log's "every attempt" semantics: a version-CONFLICT
rejection (409) produces NO audit row — nothing about the stored state changed, so
there is nothing tamper-evident to record (the same reasoning ADR-0011's Fork I already
used for its own domain). `version` is the NEW version after this write.
`updated_by_agent_id` is opt-in-when-present (hashed iff not None). Written by the
PRIVILEGED session; carries RLS (SELECT scoped to the row's own tenant_id, mirrors
automation_executions), writes remain privileged-only. Append-only via BEFORE
UPDATE/DELETE deny triggers.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class AgentStateAuditLog(Base):
    __tablename__ = "agent_state_audit_log"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state_key: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # opt-in-when-present (hashed iff not None).
    updated_by_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # created | updated
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
