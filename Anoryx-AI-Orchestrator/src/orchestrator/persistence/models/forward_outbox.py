"""forward_outbox — forward-INTENT only (O-003, ADR-0003, Fork D1).

Tenant-scoped (RLS). On accept the pipeline records that an event SHOULD be forwarded to
subscribers — it builds NO router and forwards nothing (O-005 owns the registry + the
real routing and consumes these rows). This is an honest, non-removable boundary.

ORM sync (O-006, ADR-0006): the dispatch-state columns (attempt_count, last_attempt_at,
last_error) were added to the LIVE schema by the D-004 `d004_forward_dispatch_state`
migration; the dispatcher read them via raw SQL while this ORM class stayed stale. O-006
reconciles the ORM to the live columns (code only — NO migration; the columns already
exist).
"""

from __future__ import annotations

from sqlalchemy import Integer, String, text
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
    # Dispatch-state columns (D-004 d004_forward_dispatch_state; ORM-synced in O-006).
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_attempt_at: Mapped[object | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
