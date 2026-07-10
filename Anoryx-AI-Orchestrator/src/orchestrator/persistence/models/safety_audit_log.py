"""safety_audit_log — tamper-evident GLOBAL safety-event chain (X-004).

A single hash chain across every safety-event ingest ATTEMPT (a fresh accept or an
idempotent duplicate), written by the PRIVILEGED session and mirroring identity_audit_log
(0007, ADR-0010). Append-only via BEFORE UPDATE/DELETE deny-triggers. The chain genesis +
advisory-lock domain are separated from every other chain so none can ever be confused.

CROSS-TENANT INFRA, NOT TENANT DATA: like the O-005 registry, O-009 relay, and O-010
identity chains, this is cross-tenant fleet infrastructure written only by the privileged
session — there is NO RLS here. tenant_id is a plain attribution column, not an RLS
dimension.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class SafetyAuditLog(Base):
    __tablename__ = "safety_audit_log"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_product: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    # accepted | duplicate
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # opt-in-when-present (hashed iff not None).
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
