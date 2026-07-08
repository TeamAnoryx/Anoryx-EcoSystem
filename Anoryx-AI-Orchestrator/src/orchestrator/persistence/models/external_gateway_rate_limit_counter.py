"""external_gateway_rate_limit_counters — fixed-window per-key rate-limit state
(O-013, ADR-0013).

OPERATOR-GLOBAL support infra (NOT tenant-scoped, NO RLS — internal bookkeeping, not
tenant-readable data, same posture as the advisory-lock namespaces used elsewhere in this
codebase). PRIMARY KEY (key_id, window_start) makes the per-request increment a single
atomic `INSERT ... ON CONFLICT (key_id, window_start) DO UPDATE SET request_count =
request_count + 1 RETURNING request_count` — race-safe under Postgres's MVCC with no
advisory lock needed (see persistence.repositories.increment_external_gateway_rate_limit).
`window_start` is the request's timestamp truncated to the minute (a plain fixed window,
not a sliding one — the honest, simplest correct primitive; see ADR-0013).
"""

from __future__ import annotations

from sqlalchemy import Integer, PrimaryKeyConstraint, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class ExternalGatewayRateLimitCounter(Base):
    __tablename__ = "external_gateway_rate_limit_counters"
    __table_args__ = (PrimaryKeyConstraint("key_id", "window_start"),)

    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    window_start: Mapped[object] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
