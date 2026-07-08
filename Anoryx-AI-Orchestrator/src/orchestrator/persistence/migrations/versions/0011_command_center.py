"""distribution_rollbacks (O-014, ADR-0014).

Revision ID: 0011_command_center
Revises: 0010_external_gateway
Create Date: 2026-07-08

Extends the live head (0010_external_gateway) with the O-014 rollback-correlation
persistence (ADR-0014). One table:

  distribution_rollbacks — GLOBAL tamper-evident hash chain (mirrors
                          external_gateway_audit_log/0010: privileged writes, RLS scopes
                          SELECT to the row's own tenant_id). One row per
                          OPERATOR-TRIGGERED rollback action, correlating the new
                          distribution it created with the prior distribution whose
                          signed_record it re-submitted and the distribution it
                          supersedes.

The command-center summary itself (GET /v1/admin/command-center/summary) is a pure
aggregation read over EXISTING tables (sentinel_registry, policy_distributions,
automation_executions, external_gateway_audit_log, ingest_events) — no new table, no
schema change to any of them.

The orchestrator_app role already exists (created in 0001).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_command_center"
down_revision: Union[str, None] = "0010_external_gateway"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. distribution_rollbacks — GLOBAL hash chain (privileged writes, RLS-scoped SELECT).
    #    Mirrors external_gateway_audit_log/0010.
    # ------------------------------------------------------------------ #
    op.create_table(
        "distribution_rollbacks",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("source_distribution_id", sa.String(64), nullable=False),
        sa.Column("superseded_distribution_id", sa.String(64), nullable=False),
        sa.Column("new_distribution_id", sa.String(64), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_dr_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_dr_row_hash_len"),
    )
    op.create_index("ix_dr_tenant_id", "distribution_rollbacks", ["tenant_id"])
    op.create_index("ix_dr_policy_id", "distribution_rollbacks", ["policy_id"])

    # ------------------------------------------------------------------ #
    # 2. Append-only enforcement (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_distribution_rollback_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'distribution_rollbacks is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_dr_deny_update BEFORE UPDATE ON distribution_rollbacks "
            "FOR EACH ROW EXECUTE FUNCTION deny_distribution_rollback_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_dr_deny_delete BEFORE DELETE ON distribution_rollbacks "
            "FOR EACH ROW EXECUTE FUNCTION deny_distribution_rollback_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 3. RLS: SELECT scoped (NULLIF); INSERT permissive (privileged-only writes);
    #    UPDATE/DELETE denied (belt-and-suspenders with the triggers).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("ALTER TABLE distribution_rollbacks ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE distribution_rollbacks FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            "CREATE POLICY dr_select ON distribution_rollbacks "
            f"FOR SELECT USING ({_NULLIF_PREDICATE})"
        )
    )
    conn.execute(
        sa.text("CREATE POLICY dr_insert ON distribution_rollbacks FOR INSERT WITH CHECK (true)")
    )
    conn.execute(
        sa.text("CREATE POLICY dr_deny_update ON distribution_rollbacks FOR UPDATE USING (false)")
    )
    conn.execute(
        sa.text("CREATE POLICY dr_deny_delete ON distribution_rollbacks FOR DELETE USING (false)")
    )

    # ------------------------------------------------------------------ #
    # 4. Minimal DML grants: SELECT only (inserts run on the privileged session).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("GRANT SELECT ON distribution_rollbacks TO orchestrator_app"))
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('distribution_rollbacks', 'sequence_number')
                    INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'GRANT USAGE, SELECT ON SEQUENCE %s TO orchestrator_app', seq_name);
                END IF;
            END
            $$;
            """
        )
    )


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('distribution_rollbacks', 'sequence_number')
                    INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'REVOKE USAGE, SELECT ON SEQUENCE %s FROM orchestrator_app', seq_name);
                END IF;
            END
            $$;
            """
        )
    )

    conn.execute(sa.text("DROP POLICY IF EXISTS dr_deny_delete ON distribution_rollbacks"))
    conn.execute(sa.text("DROP POLICY IF EXISTS dr_deny_update ON distribution_rollbacks"))
    conn.execute(sa.text("DROP POLICY IF EXISTS dr_insert ON distribution_rollbacks"))
    conn.execute(sa.text("DROP POLICY IF EXISTS dr_select ON distribution_rollbacks"))

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_dr_deny_update ON distribution_rollbacks"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_dr_deny_delete ON distribution_rollbacks"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_distribution_rollback_modification()"))

    op.drop_table("distribution_rollbacks")
