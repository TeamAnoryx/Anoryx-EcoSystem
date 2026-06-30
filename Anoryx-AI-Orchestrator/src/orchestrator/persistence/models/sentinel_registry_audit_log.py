"""sentinel_registry_audit_log — tamper-evident GLOBAL registry-mutation chain (O-005, ADR-0005).

A single hash chain across all registry mutations (register / modify / deregister / enable /
disable), written by the PRIVILEGED session and mirroring distribution_audit_log. Append-only
via BEFORE UPDATE/DELETE deny-triggers. The chain genesis + advisory-lock domain are separated
from the ingest and distribution chains so the three can never be confused.

OPERATOR-GLOBAL: registry mutations are operator actions, not tenant actions — there is no
tenant dimension and NO RLS (the table is privileged-owner-only). A REJECTED mutation (an
SSRF-blocked registration) is recorded with disposition='rejected' + an error_reason, so the
chain is a tamper-evident record of attempts, not only successes. endpoint, capabilities, and
error_reason follow the opt-in-when-present hash rule (hashed iff not None) so an `accepted`
link hashes identically with or without them and a set value is tamper-evident.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, Text, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class SentinelRegistryAuditLog(Base):
    __tablename__ = "sentinel_registry_audit_log"

    # Monotonic bigserial PK — defines chain order.
    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Attribution (always present — recorded after structural validation).
    sentinel_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # register | modify | deregister | enable | disable
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    # accepted | rejected (a rejected SSRF-blocked registration is recorded — tamper-evident).
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    # opt-in-when-present (hashed iff not None).
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    capabilities: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Hash-chain columns.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
