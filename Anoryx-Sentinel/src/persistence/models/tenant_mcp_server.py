"""TenantMcpServer ORM model (F-026, ADR-0032).

Per-tenant allow-list of external MCP (Model Context Protocol) servers a
tenant's agents may reach THROUGH Sentinel's governance layer. One row per
registered server per tenant.

Tenant-scoped under RLS (migration 0033, verbatim NULLIF predicate from
ADR-0005 / migrations 0006/0007/0018/0026/0028). One tenant's MCP allow-list
is never visible to another tenant's session (R4). No DELETE path — use
`is_active=False` to disable (soft-disable, mirrors webhook_config's
`enabled` column and tenants/teams/projects' own no-hard-delete convention).

server_url is validated by the F-020 SSRF guard
(orchestration.webhooks.url_guard.check_url, reused verbatim — see
src/mcp_gateway/url_guard.py) at write time, mirroring webhook_config's
"validated BEFORE any write" discipline exactly.

Honest scope (ADR-0032): this table is the GOVERNANCE SUBSTRATE — which
servers a tenant is allowed to reach, and (via src/mcp_gateway/inspection.py)
uniform PII/injection/secret inspection of MCP payload content. It does NOT
by itself proxy any MCP traffic — there is no live network call to an
external MCP server anywhere in this ADR's scope. See
docs/followups/f-026-mcp-proxy-endpoint.md for what the actual proxy needs.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base


class TenantMcpServer(Base):
    """A single tenant-scoped allow-listed external MCP server."""

    __tablename__ = "tenant_mcp_servers"

    server_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Optional scope. NULL = tenant-wide (all teams / all projects may use this server).
    team_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Operator-facing label, e.g. "internal-docs-search". Not interpreted by Sentinel.
    name: Mapped[str] = mapped_column(String(128), nullable=False)

    # The MCP server's base URL. Validated by the SSRF guard at write time
    # (src/mcp_gateway/url_guard.py) — HTTPS-only, public-IP-only, resolve-and-pin.
    # TEXT (not VARCHAR) mirrors webhook_config.target_url's precedent.
    server_url: Mapped[str] = mapped_column(Text(), nullable=False)

    # Soft enable/disable toggle — no DELETE path (mirrors webhook_config.enabled).
    is_active: Mapped[bool] = mapped_column(Boolean(), nullable=False, server_default="true")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("length(name) > 0", name="ck_tenant_mcp_servers_name_nonempty"),
        Index("ix_tenant_mcp_servers_tenant_id", "tenant_id"),
        Index("ix_tenant_mcp_servers_tenant_active", "tenant_id", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<TenantMcpServer server_id={self.server_id!r} "
            f"tenant={self.tenant_id!r} name={self.name!r} is_active={self.is_active!r}>"
        )
