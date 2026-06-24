"""WebhookDelivery ORM model (F-020, ADR-0023 §5.2).

Per-(event_id, config_id) delivery ledger for the F-020 webhook-dispatcher worker.
Mirrors the F-015 batch_files terminal-status-as-checkpoint pattern (ADR-0018 R5/R7).

At-least-once dedup semantics (ADR-0023 §5.2/§5.3):
  The UNIQUE constraint on (event_id, config_id) ensures the dispatcher INSERTs at
  most one delivery row per (source event, webhook config) pair. If the worker
  restarts mid-delivery, it finds the existing row (non-'pending') and skips — giving
  effectively-once semantics on top of the at-least-once Redis Streams delivery.

Terminal statuses — 'delivered' and 'dead_lettered' — are the worker's durable
checkpoint. Intermediate retries update `status` to 'failed' and increment `attempts`.
On retry-exhaustion the row transitions to 'dead_lettered' and a
webhook_delivery_failed audit event is appended (D3/§5.3).

Tenant-scoped under RLS (migration 0029, verbatim NULLIF predicate from ADR-0005 /
migrations 0006/0007/0018/0026/0028). No DELETE path (R6).

last_http_status_class is a BOUNDED classification string ('1xx'..'5xx') — NEVER a
response body, NEVER raw error text (D1 — metadata-only).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base

# Delivery status values — terminal: 'delivered', 'dead_lettered'.
DELIVERY_STATUSES = ("pending", "delivered", "failed", "dead_lettered")


class WebhookDelivery(Base):
    """A single delivery attempt ledger row for one (event_id, config_id) pair."""

    __tablename__ = "webhook_delivery"

    delivery_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Source audit-log event being forwarded — the UUID from events_audit_log.event_id.
    # Not an FK to events_audit_log (that table has no FK targets by design — it is
    # append-only and its primary key is a bigserial, not event_id). event_id is the
    # join key the dispatcher uses to correlate the delivery back to the source.
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Target webhook configuration — FK to webhook_config. RESTRICT prevents silent
    # config deletion while delivery rows exist.
    config_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("webhook_config.config_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Denormalized tenant_id for RLS enforcement. Always equals the source event's
    # tenant_id — verified by the dispatcher before INSERT.
    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Delivery lifecycle status.  Terminal: 'delivered' | 'dead_lettered'.
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")

    # Number of delivery attempts made so far. SMALLINT (bounded; ADR retry budget
    # is well under 32767). Incremented by the worker on each attempt.
    attempts: Mapped[int] = mapped_column(SmallInteger(), nullable=False, server_default="0")

    # Bounded HTTP status class — coarse label only, never response body or headers.
    # NULL for 'pending' rows (no attempt yet) or non-HTTP failures.
    last_http_status_class: Mapped[str | None] = mapped_column(String(8), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # At-least-once dedup key (ADR-0023 §5.2) — one row per (event, config) pair.
        UniqueConstraint("event_id", "config_id", name="uq_webhook_delivery_event_config"),
        CheckConstraint(
            "status IN ('pending', 'delivered', 'failed', 'dead_lettered')",
            name="ck_webhook_delivery_status",
        ),
        CheckConstraint(
            "last_http_status_class IS NULL OR "
            "last_http_status_class IN ('1xx', '2xx', '3xx', '4xx', '5xx')",
            name="ck_webhook_delivery_http_class",
        ),
        CheckConstraint(
            "attempts >= 0 AND attempts <= 100",
            name="ck_webhook_delivery_attempts",
        ),
        Index("ix_webhook_delivery_tenant_id", "tenant_id"),
        Index("ix_webhook_delivery_config_id", "config_id"),
        Index("ix_webhook_delivery_status", "tenant_id", "status"),
        # Composite index for the dedup query: SELECT WHERE event_id=? AND config_id=?
        Index("ix_webhook_delivery_event_config", "event_id", "config_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<WebhookDelivery delivery_id={self.delivery_id!r} "
            f"event_id={self.event_id!r} config_id={self.config_id!r} "
            f"status={self.status!r} attempts={self.attempts!r}>"
        )
