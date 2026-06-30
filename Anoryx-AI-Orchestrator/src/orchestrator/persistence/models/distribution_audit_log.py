"""distribution_audit_log — the tamper-evident GLOBAL distribution hash chain (O-004, ADR-0004).

A single chain across tenants (a tenant-scoped chain would fork per tenant), written by the
PRIVILEGED session and mirroring ingest_audit_log. Append-only via BEFORE UPDATE/DELETE
deny-triggers; RLS scopes only SELECT so a tenant reads its own links. The chain genesis is
domain-separated from the ingest chain so the two can never be confused. sentinel_id and
error_reason follow the opt-in-when-present hash rule (hashed iff not None) so a `submitted`
link hashes identically with or without them, and a set value is tamper-evident.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, Text, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class DistributionAuditLog(Base):
    __tablename__ = "distribution_audit_log"

    # Monotonic bigserial PK — defines chain order.
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Attribution (always present — recorded after structural validation).
    distribution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Nullable column (the chain is a single GLOBAL chain — the column does not constrain
    # inserts), but the append path RECORDS the real tenant_id (always folded into the hash);
    # RLS scopes SELECT to per-tenant audit rows.
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # submitted | distributed | partial | failed
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # opt-in-when-present (hashed iff not None).
    sentinel_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
