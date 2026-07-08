"""agent_messages — tenant-scoped agent-to-agent mailbox relay (O-012, ADR-0012).

Tenant-scoped (RLS, mirrors ingest_events/0001). sequence_number is the GLOBAL insert
order and IS the inbox ordering/pagination cursor directly — no separate per-recipient
sequence is needed. Sender and recipient are each identified by their F-002 stable ID
triple (team_id, project_id, agent_id); both travel under the SAME tenant_id column, so
there is no cross-tenant messaging structurally (RLS scopes both sides to one tenant).
`body` is an OPAQUE JSONB payload — relayed byte-for-byte, never inspected or acted on
by the Orchestrator (unlike O-011's automation matcher, which deliberately DOES inspect
event payloads). UNIQUE(tenant_id, idempotency_key) is the sender's own dedup key,
mirroring the O-003 ingest pipeline's dedup discipline: a resend with the same
idempotency_key is an idempotent no-op that returns the ORIGINAL message's
sequence_number/created_at unchanged.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Index, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class AgentMessage(Base):
    __tablename__ = "agent_messages"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_am_tenant_idempotency"),
        Index(
            "ix_am_inbox",
            "tenant_id",
            "recipient_team_id",
            "recipient_project_id",
            "recipient_agent_id",
            "sequence_number",
        ),
    )

    # Monotonic bigserial PK — the GLOBAL insert order, used directly as the inbox
    # ordering/pagination cursor (no separate per-recipient sequence).
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sender_team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sender_project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sender_agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recipient_agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Free-text label the sender chooses — purely descriptive metadata, NEVER
    # interpreted, parsed, or executed by the Orchestrator.
    message_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Opaque payload, relayed byte-for-byte — the Orchestrator never inspects it.
    body: Mapped[dict] = mapped_column(JSONB, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
