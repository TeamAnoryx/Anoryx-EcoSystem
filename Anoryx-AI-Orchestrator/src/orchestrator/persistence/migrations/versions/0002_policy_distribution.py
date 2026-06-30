"""Policy distribution engine: distributions, per-target status, global hash-chained audit.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-30

O-004 (ADR-0004). Extends O-003's 0001 baseline with the policy-distribution persistence
seam declared by O-001 (ADR-0001). Reuses 0001's orchestrator_app role, NULLIF tenant
predicate, RLS ENABLE+FORCE, append-only deny-trigger, and GRANT patterns verbatim.

Three tables:
  policy_distributions         — tenant-scoped (RLS). One row per submitted distribution;
                                 carries the byte-identical signed policy record for
                                 unchanged forwarding. App-role reads/writes (state moves).
  policy_distribution_targets  — tenant-scoped (RLS). Per-target independent status +
                                 bounded-retry bookkeeping (Fork C/D). App-role read/write.
  distribution_audit_log       — GLOBAL tamper-evident hash chain (mirrors
                                 ingest_audit_log). Append-only (deny-triggers). Privileged
                                 writes only; RLS scopes SELECT.

The orchestrator_app role already exists (created in 0001) — this migration only GRANTs.
Strict fail-closed RLS predicate (ADR-0005 lineage):
  tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
unsatisfiable when the GUC is unset/empty → zero rows, never a widen.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The SIX locked policy_type values. A MEMBERSHIP check only — must NOT be widened; mirrors
# the locked policy.schema.json closed set (sentinel:policy:v1, frozen at F-008 a9e2344).
_POLICY_TYPES = (
    "'budget_limit','model_allowlist','model_approval'," "'model_denylist','code_scan','data_lock'"
)
_DISTRIBUTION_STATES = "'pending','distributed','partial','failed'"
_TARGET_STATES = "'pending','distributed','failed'"
_DISPOSITIONS = "'submitted','distributed','partial','failed'"
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# Tenant-scoped tables that get the standard tenant_isolation policy (USING + WITH CHECK).
_TENANT_TABLES = ["policy_distributions", "policy_distribution_targets"]


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1a. policy_distributions — one row per submitted distribution.
    # ------------------------------------------------------------------ #
    op.create_table(
        "policy_distributions",
        sa.Column("distribution_id", sa.String(64), primary_key=True),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.BigInteger, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("policy_type", sa.String(32), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default=sa.text("'pending'")),
        # The exact signed policy record — kept verbatim for byte-identical forwarding.
        sa.Column("signed_record", postgresql.JSONB, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"state IN ({_DISTRIBUTION_STATES})", name="ck_pd_state"),
        # policy_type is a MEMBERSHIP check over the SIX locked values. It must NOT be
        # widened; mirrors the locked policy.schema.json closed set.
        sa.CheckConstraint(f"policy_type IN ({_POLICY_TYPES})", name="ck_pd_policy_type"),
        sa.CheckConstraint("length(content_hash) = 64", name="ck_pd_content_hash_len"),
    )
    op.create_index("ix_pd_tenant_id", "policy_distributions", ["tenant_id"])
    op.create_index("ix_pd_policy_id", "policy_distributions", ["policy_id"])

    # ------------------------------------------------------------------ #
    # 1b. policy_distribution_targets — per-target independent status (Fork C/D).
    # ------------------------------------------------------------------ #
    op.create_table(
        "policy_distribution_targets",
        sa.Column("target_id", sa.String(64), primary_key=True),
        sa.Column("distribution_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("sentinel_id", sa.String(128), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("max_attempts", sa.Integer, nullable=False),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("next_attempt_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("distributed_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["distribution_id"],
            ["policy_distributions.distribution_id"],
            ondelete="CASCADE",
            name="fk_pdt_distribution",
        ),
        sa.CheckConstraint(f"state IN ({_TARGET_STATES})", name="ck_pdt_state"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_pdt_attempt_count"),
        sa.CheckConstraint("max_attempts >= 1", name="ck_pdt_max_attempts"),
        # Idempotent per (distribution, target): one row per sentinel per distribution.
        sa.UniqueConstraint("distribution_id", "sentinel_id", name="uq_pdt_dist_sentinel"),
    )
    op.create_index("ix_pdt_distribution_id", "policy_distribution_targets", ["distribution_id"])
    op.create_index("ix_pdt_tenant_id", "policy_distribution_targets", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 1c. distribution_audit_log — GLOBAL hash chain (privileged writes).
    # ------------------------------------------------------------------ #
    op.create_table(
        "distribution_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("distribution_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        # tenant_id is NULLABLE (the column does not constrain inserts so the chain stays a
        # single GLOBAL chain that cannot fork per tenant), but the append path RECORDS the
        # real tenant_id; RLS scopes SELECT to per-tenant audit rows (mirrors ingest_audit_log).
        sa.Column("tenant_id", sa.String(64), nullable=True),
        sa.Column("policy_type", sa.String(32), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        # opt-in-when-present (folded into the hash iff not None).
        sa.Column("sentinel_id", sa.String(128), nullable=True),
        sa.Column("error_reason", sa.Text, nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"disposition IN ({_DISPOSITIONS})", name="ck_dal_disposition"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_dal_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_dal_row_hash_len"),
    )
    op.create_index("ix_dal_tenant_id", "distribution_audit_log", ["tenant_id"])
    op.create_index("ix_dal_distribution_id", "distribution_audit_log", ["distribution_id"])

    # ------------------------------------------------------------------ #
    # 2. Append-only enforcement on distribution_audit_log (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_distribution_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'distribution_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_dal_deny_update BEFORE UPDATE ON distribution_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_distribution_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_dal_deny_delete BEFORE DELETE ON distribution_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_distribution_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 3. RLS on the two tenant-scoped tables (ENABLE + FORCE + NULLIF policy).
    # ------------------------------------------------------------------ #
    for table in _TENANT_TABLES:
        conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        conn.execute(
            sa.text(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING ({_NULLIF_PREDICATE}) WITH CHECK ({_NULLIF_PREDICATE})"
            )
        )

    # distribution_audit_log RLS: SELECT scoped (NULLIF); INSERT permissive (privileged-only
    # writes); UPDATE/DELETE denied (USING false — belt-and-suspenders with the triggers).
    conn.execute(sa.text("ALTER TABLE distribution_audit_log ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE distribution_audit_log FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            f"CREATE POLICY dal_select ON distribution_audit_log FOR SELECT "
            f"USING ({_NULLIF_PREDICATE})"
        )
    )
    conn.execute(
        sa.text("CREATE POLICY dal_insert ON distribution_audit_log FOR INSERT WITH CHECK (true)")
    )
    conn.execute(
        sa.text("CREATE POLICY dal_deny_update ON distribution_audit_log FOR UPDATE USING (false)")
    )
    conn.execute(
        sa.text("CREATE POLICY dal_deny_delete ON distribution_audit_log FOR DELETE USING (false)")
    )

    # ------------------------------------------------------------------ #
    # 4. Minimal DML grants to orchestrator_app.
    #    SELECT, INSERT, UPDATE on the two tenant tables (UPDATE drives state transitions).
    #    SELECT only on distribution_audit_log (inserts run on the privileged session).
    #    No DDL, no BYPASSRLS, no superuser.
    # ------------------------------------------------------------------ #
    for table in ("policy_distributions", "policy_distribution_targets"):
        conn.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO orchestrator_app"))
    conn.execute(sa.text("GRANT SELECT ON distribution_audit_log TO orchestrator_app"))

    # distribution_audit_log uses a bigserial PK → grant USAGE on its sequence (mirrors 0001).
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('distribution_audit_log', 'sequence_number')
                    INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'GRANT USAGE, SELECT ON SEQUENCE %s TO orchestrator_app',
                        seq_name);
                END IF;
            END
            $$;
            """
        )
    )


def downgrade() -> None:
    conn = op.get_bind()

    # Revoke the distribution_audit_log sequence grant.
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('distribution_audit_log', 'sequence_number')
                    INTO seq_name;
                IF seq_name IS NOT NULL THEN
                    EXECUTE format(
                        'REVOKE USAGE, SELECT ON SEQUENCE %s FROM orchestrator_app',
                        seq_name);
                END IF;
            END
            $$;
            """
        )
    )

    # Drop policies, then triggers + function. (Dropping a table drops its policies too, but
    # be explicit for clarity / partial-failure recovery — mirrors 0001.)
    conn.execute(sa.text("DROP POLICY IF EXISTS dal_deny_delete ON distribution_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS dal_deny_update ON distribution_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS dal_insert ON distribution_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS dal_select ON distribution_audit_log"))
    for table in _TENANT_TABLES:
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_dal_deny_update ON distribution_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_dal_deny_delete ON distribution_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_distribution_audit_modification()"))

    # FK-safe order: targets (FK → distributions) first, then distributions, then audit.
    # Leaves 0001 objects (and the orchestrator_app role) intact.
    op.drop_table("policy_distribution_targets")
    op.drop_table("policy_distributions")
    op.drop_table("distribution_audit_log")
