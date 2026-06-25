"""ModelInventory ORM model (F-019, ADR-0022 §5.2).

The per-tenant registry of models / fine-tunes and their approval state — the data
behind F-019's default-deny enforcement. One row per (tenant_id, model_id). The
PRESENCE of an active model_approval policy for a request's scope flips that tenant
to default-deny; THIS table then decides per model: state='approved' → usable,
pending / denied / absent → denied at the gateway (src/policy/enforcement.py).

Tenant-scoped under RLS (migration 0026, same ENABLE+FORCE+tenant_isolation +
GRANT-no-DELETE pattern as 0018's bulk tables / ADR-0005). One tenant's inventory
is never visible or usable by another (R4).

State is the CURRENT decision; the tamper-evident HISTORY of every transition lives
in the append-only hash-chained audit log (the operator events), not here — a
transition mutates `state` and appends an audited event atomically (ADR-0022 §7.4/5).
`approved_by` / `approved_at` record the operator + time of the most recent decision
(approve or deny); NULL until the first operator transition.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base

# Valid model types and states (DB CHECK-constrained; mirrored in the repository).
MODEL_TYPES = ("base", "fine_tune")
INVENTORY_STATES = ("pending", "approved", "denied")


class ModelInventory(Base):
    """A single tenant-scoped model/fine-tune inventory row with its approval state."""

    __tablename__ = "model_inventory"

    inventory_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # The model identifier as it appears on a /v1 request body.model.
    model_id: Mapped[str] = mapped_column(String(256), nullable=False)

    # base | fine_tune.
    model_type: Mapped[str] = mapped_column(String(16), nullable=False, server_default="base")

    # pending | approved | denied. New rows start pending (adopt-on-observe).
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")

    # Operator (admin_users.id, F-014) of the most recent decision; NULL for
    # break-glass (no per-operator identity) or before any decision. Plain nullable
    # string, not an FK — mirrors the audit log's actor_id (no coupling, allows NULL).
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # F-021 (ADR-0024): grace deadline after which this APPROVED model is denied at
    # the gateway (src/policy/enforcement.py, fail-closed). NULL = not scheduled for
    # retirement. A row with state='approved' and a non-NULL retire_at is "retiring":
    # usable until this instant, then denied. Only meaningful on approved rows; set by
    # the retire operator action, cleared by un-retire. The `state` CHECK is unchanged
    # — "retiring" is a UI-derived view of (approved + retire_at), not a stored state.
    retire_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "model_id", name="uq_model_inventory_tenant_model"),
        CheckConstraint(
            "model_type IN ('base', 'fine_tune')", name="ck_model_inventory_model_type"
        ),
        CheckConstraint(
            "state IN ('pending', 'approved', 'denied')", name="ck_model_inventory_state"
        ),
        Index("ix_model_inventory_tenant_id", "tenant_id"),
        Index("ix_model_inventory_tenant_model", "tenant_id", "model_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ModelInventory tenant={self.tenant_id!r} "
            f"model={self.model_id!r} state={self.state!r}>"
        )
