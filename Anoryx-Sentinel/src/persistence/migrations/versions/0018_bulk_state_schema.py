"""F-015 bulk pipeline state schema: batches + batch_files (ADR-0018 §9 D8).

Revision ID: 0018
Revises: 0017
Create Date: 2026-06-22

Creates the two tenant-scoped state tables for the async bulk pipeline:

1. batches      — one row per submitted batch; UNIQUE (tenant_id, idempotency_key)
                  enforces idempotency (R5 / vector 9).
2. batch_files  — one row per file; terminal status = the checkpoint (R5/R7).

Both tables get RLS (ENABLE + FORCE + tenant_isolation using the strict NULLIF
predicate, verbatim from 0006/0007 / ADR-0005 fail-closed form) and a GRANT of
SELECT, INSERT, UPDATE to sentinel_app (a NEW table has NO access by default;
without the GRANT a tenant session cannot touch it). No DELETE — there is no
hard-delete path (no silent drops; DLQ is a status, R6).

This migration does NOT touch events_audit_log — the 5 batch_* event variants land
separately in 0019 (4-site, api-architect-coupled). DOWN fully reverses; never
touches data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The strict NULLIF predicate (verbatim from 0006/0007 / ADR-0005 fail-closed form).
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

    # ------------------------------------------------------------------ batches
    op.create_table(
        "batches",
        sa.Column("batch_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        # Optional target model the files are destined for. When set, F-008 model
        # allow/deny policy is enforced per file (ADR-0018 §5 / vector 13). NULL =
        # detectors-only scan (F-008 model/budget is N/A — a scan calls no model).
        sa.Column("model", sa.String(256), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("total_files", sa.Integer(), nullable=False, server_default="0"),
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
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_batches_tenant_idem"),
        sa.CheckConstraint("status IN ('queued','running','completed')", name="ck_batches_status"),
        sa.CheckConstraint("total_files >= 0", name="ck_batches_total_files"),
    )
    op.create_index("ix_batches_tenant_id", "batches", ["tenant_id"])

    # -------------------------------------------------------------- batch_files
    op.create_table(
        "batch_files",
        sa.Column("file_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "batch_id",
            sa.String(64),
            sa.ForeignKey("batches.batch_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("object_key", sa.String(512), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("outcome", sa.String(16), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_class", sa.String(64), nullable=True),
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
        sa.UniqueConstraint("batch_id", "object_key", name="uq_batch_files_batch_object"),
        sa.CheckConstraint(
            "status IN ('queued','running','done','blocked','dead_lettered')",
            name="ck_batch_files_status",
        ),
        sa.CheckConstraint(
            "outcome IS NULL OR outcome IN ('allowed','blocked','redacted')",
            name="ck_batch_files_outcome",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_batch_files_attempt_count"),
    )
    op.create_index("ix_batch_files_tenant_id", "batch_files", ["tenant_id"])
    op.create_index("ix_batch_files_batch_id", "batch_files", ["batch_id"])
    op.create_index("ix_batch_files_batch_status", "batch_files", ["batch_id", "status"])

    # ----------------------------------------------------------------- RLS+GRANT
    _enable_rls(conn, "batches")
    _enable_rls(conn, "batch_files")


def downgrade() -> None:
    conn = op.get_bind()

    # Drop child first (FK), then parent. Revoke + drop RLS before dropping tables.
    for table in ("batch_files", "batches"):
        conn.execute(sa.text(f"REVOKE SELECT, INSERT, UPDATE ON {table} FROM sentinel_app"))
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        conn.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_batch_files_batch_status", table_name="batch_files")
    op.drop_index("ix_batch_files_batch_id", table_name="batch_files")
    op.drop_index("ix_batch_files_tenant_id", table_name="batch_files")
    op.drop_table("batch_files")

    op.drop_index("ix_batches_tenant_id", table_name="batches")
    op.drop_table("batches")
