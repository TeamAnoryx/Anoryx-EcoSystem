"""automation_rules — tenant-scoped cross-module automation-rules engine (O-011, ADR-0011).

One row per tenant-defined rule: react to an event of `trigger_event_type` (optionally
filtered by `trigger_source_product`), match a FLAT scalar-equality `trigger_conditions`
dict against the event payload's top-level fields, and — on a match — trigger exactly ONE
closed, pre-existing, already-audited Orchestrator action (`action_type`, v1 supports only
`redistribute_policy`). RLS-scoped (mirrors ingest_events/0001, identity_events/0007) —
reads/writes run under the tenant's `get_tenant_session`. Bounded per tenant by
ORCH_AUTOMATION_MAX_RULES_PER_TENANT, enforced at INSERT time by the router (COUNT under
the tenant session), not by a DB-level trigger.
"""

from __future__ import annotations

from sqlalchemy import Boolean, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class AutomationRule(Base):
    __tablename__ = "automation_rules"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_ar_tenant_name"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    trigger_event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Optional filter; NULL means "any source_product".
    trigger_source_product: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # A FLAT dict of payload-top-level-field -> expected JSON scalar value. Equality only —
    # no nesting, no regex, no operators, no code (the security property IS the simplicity).
    trigger_conditions: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    # v1 supports exactly ONE action type — CHECK constraint closed to 'redistribute_policy'
    # (migration-level), re-asserted at the router boundary (422, not a DB 500).
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # For redistribute_policy: {"distribution_id": "<existing distribution id, same tenant>"}.
    action_config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
