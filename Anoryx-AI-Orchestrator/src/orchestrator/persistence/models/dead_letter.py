"""dead_letter_queue — the O-002 failure-envelope store (O-003, ADR-0003).

Tenant-scoped (RLS, Fork E1 closes O-002 LOW-2). Holds the FULL failure-envelope the DLQ
preserves and that a future replay-from-DLQ re-drives. original_envelope is the original
preserved; the classifying columns (event_type/source_product/source_sequence) allow
triage WITHOUT opening the body. tenant_id is best-effort from the payload and may be
NULL (payload-invalid) — the strict NULLIF RLS predicate then makes the row invisible to
every tenant (fail-closed; operator/privileged-only). DLQ rows are written via the
PRIVILEGED session (BYPASSRLS) precisely because a NULL-tenant row would fail the app
role's WITH CHECK; RLS still scopes DLQ READS. max_attempts_exceeded is the terminal
reason that bounds re-drive (DLQ-poisoning defense).
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class DeadLetterEntry(Base):
    __tablename__ = "dead_letter_queue"

    dlq_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    original_envelope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    first_failed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_failed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Classifying fields (triage without the body).
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_product: Mapped[str] = mapped_column(String(32), nullable=False)
    source_sequence: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Best-effort tenant; NULL when payload-invalid (RLS-invisible to tenants).
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
