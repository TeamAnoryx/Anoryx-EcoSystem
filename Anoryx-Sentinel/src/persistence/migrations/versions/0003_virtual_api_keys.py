"""Virtual API keys table with HMAC-SHA256 fingerprint storage.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-15

SECURITY: No plaintext keys are stored. key_fingerprint = HMAC-SHA256(key, secret).
Auth compares HMACs (constant-time) — never raw key strings.
The row is the authoritative source of tenant/team/project/agent IDs.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "virtual_api_keys",
        sa.Column("key_id", sa.String(64), primary_key=True, nullable=False),
        # HMAC-SHA256 hex digest (64 chars). Never the plaintext key.
        sa.Column("key_fingerprint", sa.String(64), nullable=False, unique=True),
        # Four stable IDs — authoritative (server-resolved).
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "team_id",
            sa.String(64),
            sa.ForeignKey("teams.team_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.String(64),
            sa.ForeignKey("projects.project_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        # agent_id: slug VARCHAR(64). No FK — agent may not exist at key-creation time.
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("label", sa.String(256), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        # key_fingerprint must be exactly 64 hex chars (SHA-256 = 32 bytes).
        sa.CheckConstraint(
            "length(key_fingerprint) = 64",
            name="ck_vak_fingerprint_len",
        ),
    )
    op.create_index("ix_vak_key_fingerprint", "virtual_api_keys", ["key_fingerprint"], unique=True)
    op.create_index("ix_vak_tenant_id", "virtual_api_keys", ["tenant_id"])
    op.create_index("ix_vak_project_id", "virtual_api_keys", ["project_id"])


def downgrade() -> None:
    op.drop_table("virtual_api_keys")
