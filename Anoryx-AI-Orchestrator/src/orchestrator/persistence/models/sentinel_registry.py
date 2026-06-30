"""sentinel_registry — the registry of Sentinel instances (O-005, ADR-0005).

OPERATOR-GLOBAL infra (NOT tenant-scoped): one row per registered Sentinel instance,
written + read on the PRIVILEGED session. It carries the validated endpoint, a NON-SECRET
peer-auth reference, the statically DECLARED capabilities (supported policy_types, Fork C1),
and the current health status maintained by the health-check subsystem (Fork A1). The
endpoint is SSRF-validated at registration and re-validated before every outbound use; this
model stores the validated value, it does not validate. No RLS (no tenant dimension);
per-tenant scoping is O-006.

health_status: unknown | healthy | degraded | unreachable. "healthy" means reachable per the
documented contract (a reachability probe), NOT verified-enforcing (ADR-0005 honesty
boundary E1). peer_auth_ref is a label (e.g. 'global' = use the shared SENTINEL_ADMIN_TOKEN);
the secret itself is NEVER stored here (per-target credentials → O-008).
"""

from __future__ import annotations

from sqlalchemy import Boolean, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class SentinelRegistry(Base):
    __tablename__ = "sentinel_registry"

    # Logical instance id (matches the O-004 router sentinel_id pattern). Operator-chosen.
    sentinel_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    # SSRF-validated base URL (validation lives in coordination.endpoint_validation).
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    # Non-secret peer-auth reference. 'global' = use the shared SENTINEL_ADMIN_TOKEN (interim);
    # per-target credentials are O-008. A secret is NEVER stored here.
    peer_auth_ref: Mapped[str] = mapped_column(
        String(128), nullable=False, server_default=text("'global'")
    )
    # Declared supported policy_types (static, Fork C1) — a JSON array of strings.
    capabilities: Mapped[object] = mapped_column(JSONB, nullable=False)
    # unknown | healthy | degraded | unreachable (maintained by run_health_cycle).
    health_status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'unknown'")
    )
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    last_checked_at: Mapped[object | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    last_healthy_at: Mapped[object | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    # Operator pause without deregistering (excluded from coordinated pushes when false).
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
