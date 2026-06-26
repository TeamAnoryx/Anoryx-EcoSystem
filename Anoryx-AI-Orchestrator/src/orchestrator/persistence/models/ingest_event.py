"""ingest_events — the dedup + metadata + replay-source store (O-003, ADR-0003).

Tenant-scoped (RLS). The UNIQUE idempotency_key is the consumer dedup gate (Fork B1).
The full locked payload is kept so a future replay can re-emit it; the metadata-only GET
read seam that projects just the join keys is O-006. source_sequence is the envelope's
monotonic per-source sequence — the inclusive lower bound a future from_sequence replay
uses. content_hash distinguishes a benign duplicate from an idempotency_conflict.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class IngestEvent(Base):
    __tablename__ = "ingest_events"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    envelope_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # The bus dedup key (== payload.event_id). UNIQUE = the persistent dedup gate.
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    source_product: Mapped[str] = mapped_column(String(32), nullable=False)
    source_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    causation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # F-002 metadata projection (the join keys + type + time).
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    team_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # The full locked F-002 event (replay re-emits it).
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
