"""identity_events — tenant-scoped cross-product identity/access correlation (O-010, ADR-0010).

One normalized "who accessed what, where" record per (source_product, idempotency_key): a
principal in Sentinel, Delta, or Rendly took an action, at a tenant, optionally against a
target. RLS-scoped (mirrors ingest_events, 0001) — reads/writes run under the tenant's
`get_tenant_session`. Idempotent by construction: a retried push with the same
(source_product, idempotency_key) is a no-op, never a duplicate row.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class IdentityEvent(Base):
    __tablename__ = "identity_events"
    __table_args__ = (
        UniqueConstraint("source_product", "idempotency_key", name="uq_ide_source_idempotency"),
    )

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_product: Mapped[str] = mapped_column(String(16), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[object] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    received_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
