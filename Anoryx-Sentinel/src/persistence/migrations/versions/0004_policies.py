"""Policies and policy_versions tables with monotonic version enforcement.

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-15

MONOTONICITY: A BEFORE INSERT trigger on policy_versions raises if the new
policy_version is not strictly greater than the current max version for that
policy_id. This is defense-in-depth on top of the repository-layer check.

SIGNATURE: Stored as compact-JWS string (three dot-separated base64url segments).
Format is enforced by CHECK constraint. Crypto-verification deferred to F-008.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SIGNATURE_MAX = 4096


def upgrade() -> None:
    # ------------------------------------------------------------------
    # policies (current state — one row per policy_id)
    # ------------------------------------------------------------------
    op.create_table(
        "policies",
        sa.Column("policy_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("policy_type", sa.String(64), nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("current_version", sa.BigInteger, nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(_SIGNATURE_MAX), nullable=False),
        sa.Column("policy_payload", sa.Text, nullable=False),
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
        sa.CheckConstraint(
            "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist')",
            name="ck_policies_policy_type",
        ),
        sa.CheckConstraint("current_version >= 1", name="ck_policies_version_positive"),
        sa.CheckConstraint(
            f"length(signature) >= 16 AND length(signature) <= {_SIGNATURE_MAX}",
            name="ck_policies_signature_length",
        ),
    )
    op.create_index("ix_policies_tenant_id", "policies", ["tenant_id"])
    op.create_index("ix_policies_tenant_type", "policies", ["tenant_id", "policy_type"])

    # ------------------------------------------------------------------
    # policy_versions (full history — append-only, (policy_id, version) unique)
    # ------------------------------------------------------------------
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "policy_id",
            sa.String(64),
            sa.ForeignKey("policies.policy_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.BigInteger, nullable=False),
        sa.Column("policy_type", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(_SIGNATURE_MAX), nullable=False),
        sa.Column("policy_payload", sa.Text, nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("policy_id", "policy_version", name="uq_policy_versions_id_ver"),
        sa.CheckConstraint("policy_version >= 1", name="ck_pv_version_positive"),
        sa.CheckConstraint(
            "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist')",
            name="ck_pv_policy_type",
        ),
        sa.CheckConstraint(
            f"length(signature) >= 16 AND length(signature) <= {_SIGNATURE_MAX}",
            name="ck_pv_signature_length",
        ),
    )
    op.create_index("ix_pv_policy_id", "policy_versions", ["policy_id"])
    op.create_index("ix_pv_policy_id_version", "policy_versions", ["policy_id", "policy_version"])
    op.create_index("ix_pv_tenant_id", "policy_versions", ["tenant_id"])

    # ------------------------------------------------------------------
    # Monotonicity trigger: enforce policy_version is strictly increasing.
    # Defense-in-depth on top of the repository-layer check.
    # ------------------------------------------------------------------
    conn = op.get_bind()
    conn.execute(sa.text("""
            CREATE OR REPLACE FUNCTION enforce_policy_version_monotonicity()
            RETURNS TRIGGER AS $$
            DECLARE
                current_max BIGINT;
            BEGIN
                SELECT MAX(policy_version) INTO current_max
                FROM policy_versions
                WHERE policy_id = NEW.policy_id;

                IF current_max IS NOT NULL AND NEW.policy_version <= current_max THEN
                    RAISE EXCEPTION
                        'policy_version monotonicity violated: '
                        'incoming version % is not greater than current max % '
                        'for policy_id %',
                        NEW.policy_version, current_max, NEW.policy_id;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            """))
    conn.execute(sa.text("""
            CREATE TRIGGER trg_policy_versions_monotonicity
            BEFORE INSERT ON policy_versions
            FOR EACH ROW EXECUTE FUNCTION enforce_policy_version_monotonicity();
            """))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DROP TRIGGER IF EXISTS trg_policy_versions_monotonicity ON policy_versions")
    )
    conn.execute(sa.text("DROP FUNCTION IF EXISTS enforce_policy_version_monotonicity()"))
    op.drop_table("policy_versions")
    op.drop_table("policies")
