"""ingest_audit_log — the tamper-evident GLOBAL hash chain (O-003, ADR-0003).

A single chain across tenants (a tenant-scoped chain would fork per tenant), written by
the PRIVILEGED session (rule 7: privileged role for chain ops; mirrors F-003
events_audit_log). Append-only via BEFORE UPDATE/DELETE deny-triggers; RLS scopes only
SELECT so a tenant reads its own links. dlq_reason/dlq_id follow the opt-in-when-present
hash rule (hashed iff not None) so accepted rows are byte-identical to the chain-without-
them form and a set value is tamper-evident.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class IngestAuditLog(Base):
    __tablename__ = "ingest_audit_log"

    # Monotonic bigserial PK — defines chain order.
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Payload-derived attribution. NULLABLE because a dead_lettered link for a
    # payload-invalid envelope has no trustworthy payload IDs; a DB CHECK requires them
    # non-null for accepted links (full attribution on the happy path). The hash folds
    # None for absent fields (omission-attack-safe).
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    team_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Envelope-derived (always present — the envelope passed structural validation).
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_id: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    source_product: Mapped[str] = mapped_column(String(32), nullable=False)
    # accepted | deduped | dead_lettered
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # opt-in-when-present (hashed iff not None).
    dlq_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dlq_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
