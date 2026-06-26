"""forward_outbox — forward-INTENT only (O-003, ADR-0003, Fork D1).

Tenant-scoped (RLS). On accept the pipeline records that an event SHOULD be forwarded to
subscribers — it builds NO router and forwards nothing (O-005 owns the registry + the
real routing and consumes these rows). This is an honest, non-removable boundary.
"""

from __future__ import annotations

from sqlalchemy import String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class ForwardOutbox(Base):
    __tablename__ = "forward_outbox"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    # pending only at O-003; O-005 transitions it.
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'pending'")
    )
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
