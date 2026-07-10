"""safety_events — tenant-scoped cross-product safety-inspection outcome (X-004).

One normalized "a local safety inspection produced a non-pass outcome" record per
(source_product, idempotency_key): Sentinel, Delta, or Rendly each push ONE record after
their OWN in-product content inspection fires. RLS-scoped (mirrors identity_events, 0007):
reads/writes run under the tenant's `get_tenant_session`. Idempotent by construction: a
retried push with the same (source_product, idempotency_key) is a no-op, never a duplicate
row.

METADATA ONLY: no message/prompt content is ever persisted here — only category/outcome/
target (opaque id)/tenant/timestamps, exactly as the contract bounds it.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class SafetyEvent(Base):
    __tablename__ = "safety_events"
    __table_args__ = (
        UniqueConstraint("source_product", "idempotency_key", name="uq_safe_source_idempotency"),
    )

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_product: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[object] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    received_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
