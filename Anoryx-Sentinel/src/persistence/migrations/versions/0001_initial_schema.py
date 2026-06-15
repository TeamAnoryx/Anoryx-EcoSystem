"""Initial schema: tenants, teams, projects, agents, users.

Revision ID: 0001
Revises: (none)
Create Date: 2026-06-15

Passwords are stored as Argon2id PHC strings (argon2-cffi). The password_hash
column is VARCHAR(512) to accommodate the full PHC string including parameters,
salt, and digest. Plaintext passwords are NEVER stored.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # tenants
    # ------------------------------------------------------------------
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
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
    )

    # ------------------------------------------------------------------
    # teams
    # ------------------------------------------------------------------
    op.create_table(
        "teams",
        sa.Column("team_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
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
    )
    op.create_index("ix_teams_tenant_id", "teams", ["tenant_id"])
    op.create_index(
        "ix_teams_tenant_name", "teams", ["tenant_id", "name"], unique=True
    )

    # ------------------------------------------------------------------
    # projects
    # ------------------------------------------------------------------
    op.create_table(
        "projects",
        sa.Column("project_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "team_id",
            sa.String(64),
            sa.ForeignKey("teams.team_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
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
    )
    op.create_index("ix_projects_team_id", "projects", ["team_id"])
    op.create_index("ix_projects_tenant_id", "projects", ["tenant_id"])
    op.create_index(
        "ix_projects_team_name", "projects", ["team_id", "name"], unique=True
    )

    # ------------------------------------------------------------------
    # agents (registry of internal Sentinel component slugs)
    # ------------------------------------------------------------------
    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # ------------------------------------------------------------------
    # users (passwords: Argon2id PHC hash only — NEVER plaintext)
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("email", sa.String(320), nullable=False),
        # Argon2id PHC string. Never plaintext. VARCHAR(512) fits max PHC string length.
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("is_superuser", sa.Boolean, nullable=False, server_default="false"),
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
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index(
        "ix_users_tenant_email", "users", ["tenant_id", "email"], unique=True
    )


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("agents")
    op.drop_table("projects")
    op.drop_table("teams")
    op.drop_table("tenants")
