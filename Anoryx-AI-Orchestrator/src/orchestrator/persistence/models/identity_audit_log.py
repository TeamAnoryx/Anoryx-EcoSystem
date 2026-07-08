"""identity_audit_log — tamper-evident GLOBAL identity-event chain (O-010, ADR-0010).

A single hash chain across every identity-event ingest ATTEMPT (a fresh accept or an
idempotent duplicate), written by the PRIVILEGED session and mirroring relay_audit_log /
sentinel_registry_audit_log. Append-only via BEFORE UPDATE/DELETE deny-triggers. The chain
genesis + advisory-lock domain are separated from every other chain so none can ever be
confused.

CROSS-TENANT INFRA, NOT TENANT DATA: like the O-005 registry and O-009 relay chains, this is
cross-tenant fleet infrastructure written only by the privileged session — there is NO RLS
here. tenant_id is a plain attribution column, not an RLS dimension.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class IdentityAuditLog(Base):
    __tablename__ = "identity_audit_log"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_product: Mapped[str] = mapped_column(String(16), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
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
