"""relay_audit_log — tamper-evident GLOBAL relay-dispatch chain (O-009, ADR-0009).

A single hash chain across every relay-dispatch attempt (forwarded to Sentinel and actually
answered, blocked before any outbound call, or failed at the transport layer), written by the
PRIVILEGED session and mirroring distribution_audit_log / sentinel_registry_audit_log.
Append-only via BEFORE UPDATE/DELETE deny-triggers. The chain genesis + advisory-lock domain
are separated from the ingest, distribution, and registry chains so none can ever be confused.

CROSS-TENANT INFRA, NOT TENANT DATA: like the O-005 registry, the relay dispatches to a
registry-wide Sentinel fleet and is written only by the privileged session — there is NO RLS
here. tenant_id is carried as a plain attribution column (whose traffic this was), not an RLS
dimension.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class RelayAuditLog(Base):
    __tablename__ = "relay_audit_log"

    # Monotonic bigserial PK — defines chain order.
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Attribution (always present — recorded after structural validation).
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_product: Mapped[str] = mapped_column(String(16), nullable=False)
    sentinel_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_path: Mapped[str] = mapped_column(String(256), nullable=False)
    # forwarded | blocked | failed
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # opt-in-when-present (hashed iff not None).
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
