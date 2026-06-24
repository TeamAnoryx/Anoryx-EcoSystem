"""F-019 model inventory state table (ADR-0022 §5.2).

Revision ID: 0026
Revises: 0025
Create Date: 2026-06-24

Creates the per-tenant `model_inventory` table — the registry of models / fine-tunes
and their approval state (pending | approved | denied) that backs F-019's default-deny
enforcement. One row per (tenant_id, model_id).

Tenant-scoped: ENABLE + FORCE ROW LEVEL SECURITY with the strict NULLIF
tenant_isolation predicate (verbatim from 0006/0007/0018 / ADR-0005 fail-closed form)
and a GRANT of SELECT, INSERT, UPDATE to sentinel_app (a NEW table has NO access by
default; without the GRANT a tenant session cannot touch it). No DELETE — inventory
rows are never hard-deleted (a model is denied, not erased; the audited history is
append-only, R6/ADR-0022 §7.5).

DOWN fully reverses (revoke + drop RLS + drop indexes + drop table); never touches
data. Round-trip verified at STEP 9.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The strict NULLIF predicate (verbatim from 0006/0007/0018 / ADR-0005 fail-closed form).
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(conn, table: str) -> None:
    conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING ({_NULLIF_PREDICATE})
            WITH CHECK ({_NULLIF_PREDICATE})
            """
        )
    )
    conn.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO sentinel_app"))


def upgrade() -> None:
    conn = op.get_bind()

    op.create_table(
        "model_inventory",
        sa.Column("inventory_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("model_id", sa.String(256), nullable=False),
        sa.Column("model_type", sa.String(16), nullable=False, server_default="base"),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("approved_by", sa.String(64), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.UniqueConstraint("tenant_id", "model_id", name="uq_model_inventory_tenant_model"),
        sa.CheckConstraint(
            "model_type IN ('base', 'fine_tune')", name="ck_model_inventory_model_type"
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'approved', 'denied')", name="ck_model_inventory_state"
        ),
    )
    op.create_index("ix_model_inventory_tenant_id", "model_inventory", ["tenant_id"])
    op.create_index("ix_model_inventory_tenant_model", "model_inventory", ["tenant_id", "model_id"])

    _enable_rls(conn, "model_inventory")


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text("REVOKE SELECT, INSERT, UPDATE ON model_inventory FROM sentinel_app"))
    conn.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON model_inventory"))
    conn.execute(sa.text("ALTER TABLE model_inventory DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_model_inventory_tenant_model", table_name="model_inventory")
    op.drop_index("ix_model_inventory_tenant_id", table_name="model_inventory")
    op.drop_table("model_inventory")
