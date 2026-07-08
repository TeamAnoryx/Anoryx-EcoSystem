"""agent_state — tenant-scoped shared key-value state store, optimistic concurrency (O-012).

Tenant-scoped (RLS, mirrors agent_messages). UNIQUE(tenant_id, state_key) — one row per
(tenant, key). `version` is the optimistic-concurrency token: it starts at 1 and is
incremented by EXACTLY 1 on every successful write (never a distributed-consensus
mechanism — a single Postgres instance's row is the sole source of truth for a key's
current version). `updated_by_agent_id` is opt-in attribution: the caller MAY say which
agent made this write; it is never required and never validated against an existing
agent registry (none exists).
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class AgentState(Base):
    __tablename__ = "agent_state"
    __table_args__ = (UniqueConstraint("tenant_id", "state_key", name="uq_as_tenant_state_key"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state_key: Mapped[str] = mapped_column(String(256), nullable=False)
    state_value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("1"))
    updated_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_by_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
