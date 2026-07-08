"""external_gateway_audit_log — tamper-evident GLOBAL third-party-access audit chain
(O-013, ADR-0013).

Written by the PRIVILEGED session (mirrors agent_messaging_audit_log structurally), and
— like agent_messaging_audit_log / automation_executions — this table CARRIES RLS: it is
genuinely tenant-relevant audit data a tenant could read back, so SELECT is RLS-scoped to
the row's own tenant_id while writes remain privileged-only. Append-only via BEFORE
UPDATE/DELETE deny triggers.

Records every request attempt where a key was resolved to a tenant — 'allowed',
'scope_denied', 'rate_limited', and 'revoked' all get a chain link (mirrors
agent_messaging_audit_log's "every attempt" semantics: the whole point of a governance
gateway is a durable record of what was tried, not only what succeeded). A request
bearing an UNKNOWN or malformed key resolves no tenant at all, so it has no chain-audit
home here (mirrors PrincipalAuthError's identical non-audited-401 precedent) — never
implied to be logged elsewhere.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class ExternalGatewayAuditLog(Base):
    __tablename__ = "external_gateway_audit_log"

    sequence_number: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    route: Mapped[str] = mapped_column(String(128), nullable=False)
    # allowed | scope_denied | rate_limited | revoked
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
