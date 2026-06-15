"""RBAC: role_assignments table + Postgres Row-Level Security (RLS).

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-15

RLS is ENABLED with FORCE ROW LEVEL SECURITY on all tenant-scoped tables.
This means even the table owner cannot bypass the policy without explicit
BYPASSRLS privilege. Tenant isolation is enforced at the DB layer, not
just the application layer.

RLS policy: rows are visible/modifiable only when current_setting(
'app.current_tenant_id') matches the row's tenant_id. Superusers and the
migration user (BYPASSRLS) can see all rows for admin operations.

The sentinel DB user used by migrations has BYPASSRLS (set in DB setup).
Application connections set 'app.current_tenant_id' before queries.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables that get tenant-isolation RLS.
_TENANT_SCOPED_TABLES = [
    "teams",
    "projects",
    "users",
]


def upgrade() -> None:
    # ------------------------------------------------------------------
    # role_assignments
    # ------------------------------------------------------------------
    op.create_table(
        "role_assignments",
        sa.Column("role_assignment_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "team_id",
            sa.String(64),
            sa.ForeignKey("teams.team_id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "project_id",
            sa.String(64),
            sa.ForeignKey("projects.project_id", ondelete="CASCADE"),
            nullable=True,
        ),
        # Validated against VALID_ROLES in repo. DB stores the string.
        sa.Column("role", sa.String(64), nullable=False),
        sa.Column("granted_by", sa.String(64), nullable=True),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "role IN ('admin', 'operator', 'viewer', 'auditor')",
            name="ck_ra_role",
        ),
    )
    op.create_index("ix_ra_user_id", "role_assignments", ["user_id"])
    op.create_index("ix_ra_tenant_id", "role_assignments", ["tenant_id"])
    op.create_index(
        "ix_ra_tenant_user_role",
        "role_assignments",
        ["tenant_id", "user_id", "role"],
    )

    # ------------------------------------------------------------------
    # Enable Row-Level Security on tenant-scoped tables.
    # FORCE ROW LEVEL SECURITY ensures even the table owner is constrained.
    # ------------------------------------------------------------------
    conn = op.get_bind()

    for table in _TENANT_SCOPED_TABLES:
        conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        # Permissive SELECT/INSERT/UPDATE/DELETE policy: row tenant_id must match
        # the session-local 'app.current_tenant_id' setting.
        # Superusers (BYPASSRLS) see all rows.
        conn.execute(
            sa.text(
                f"""
                CREATE POLICY tenant_isolation ON {table}
                USING (
                    tenant_id = current_setting('app.current_tenant_id', true)
                    OR current_setting('app.current_tenant_id', true) IS NULL
                )
                WITH CHECK (
                    tenant_id = current_setting('app.current_tenant_id', true)
                    OR current_setting('app.current_tenant_id', true) IS NULL
                )
                """
            )
        )

    # role_assignments also gets RLS (tenant_id present).
    for table in ["role_assignments"]:
        conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        conn.execute(
            sa.text(
                f"""
                CREATE POLICY tenant_isolation ON {table}
                USING (
                    tenant_id = current_setting('app.current_tenant_id', true)
                    OR current_setting('app.current_tenant_id', true) IS NULL
                )
                WITH CHECK (
                    tenant_id = current_setting('app.current_tenant_id', true)
                    OR current_setting('app.current_tenant_id', true) IS NULL
                )
                """
            )
        )


def downgrade() -> None:
    conn = op.get_bind()

    for table in _TENANT_SCOPED_TABLES + ["role_assignments"]:
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        conn.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
        conn.execute(sa.text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))

    op.drop_table("role_assignments")
