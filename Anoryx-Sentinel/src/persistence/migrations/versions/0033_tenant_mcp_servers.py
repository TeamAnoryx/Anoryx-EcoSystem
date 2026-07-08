"""F-026 tenant_mcp_servers table — per-tenant MCP server allow-list (ADR-0032).

Revision ID: 0033
Revises: 0032
Create Date: 2026-07-08

Creates the `tenant_mcp_servers` table: the per-tenant registry of external
MCP (Model Context Protocol) servers a tenant's agents are allowed to reach
THROUGH Sentinel's governance layer (F-026, ADR-0032).

Design (mirrors webhook_config / migration 0028 exactly — same shape, same
per-tenant external-endpoint-allowlist problem):
  - server_id      VARCHAR(64)  — PK, opaque UUID (four-stable-IDs convention).
  - server_url     TEXT         — validated at write AND re-validated at any
                                   future connect by the SSRF guard
                                   (src/mcp_gateway/url_guard.py, reuses the
                                   F-020 orchestration.webhooks.url_guard
                                   verbatim). TEXT (not VARCHAR) for parity
                                   with webhook_config.target_url.
  - name           VARCHAR(128) — operator-facing label, non-empty (CHECK).
  - is_active      BOOLEAN      — soft-enable/disable; no DELETE path.
  - team_id/project_id — optional scope; NULL = tenant-wide.
  - created_at / updated_at — standard audit timestamps.

Tenant-scoped RLS (verbatim fail-closed NULLIF predicate from ADR-0005,
established in migrations 0006/0007/0018/0026/0028): ENABLE + FORCE +
DROP-IF-EXISTS + CREATE POLICY + GRANT SELECT/INSERT/UPDATE to sentinel_app
(no DELETE — soft-disable via 'is_active', same as webhook_config).

Down revision: 0032 (verified current head; 0033 is the first F-026 migration).

Reversible: downgrade() revokes, drops policy, disables RLS, drops table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: Union[str, None] = "0032"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "tenant_mcp_servers"

# Fail-closed NULLIF predicate — verbatim from ADR-0005 / migrations 0006/0007/0018/0026/0028.
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(conn) -> None:
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY tenant_isolation ON {_TABLE}
            USING ({_NULLIF_PREDICATE})
            WITH CHECK ({_NULLIF_PREDICATE})
            """
        )
    )
    conn.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {_TABLE} TO sentinel_app"))


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("server_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("team_id", sa.String(64), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("server_url", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("length(name) > 0", name="ck_tenant_mcp_servers_name_nonempty"),
    )

    op.create_index("ix_tenant_mcp_servers_tenant_id", _TABLE, ["tenant_id"])
    op.create_index("ix_tenant_mcp_servers_tenant_active", _TABLE, ["tenant_id", "is_active"])

    conn = op.get_bind()
    _enable_rls(conn)


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text(f"REVOKE SELECT, INSERT, UPDATE ON {_TABLE} FROM sentinel_app"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_tenant_mcp_servers_tenant_active", table_name=_TABLE)
    op.drop_index("ix_tenant_mcp_servers_tenant_id", table_name=_TABLE)
    op.drop_table(_TABLE)
