"""automation_rules + automation_executions — cross-module automation engine (O-011).

Revision ID: 0008_automation_engine
Revises: 0007_identity_events
Create Date: 2026-07-08

Extends the live head (0007_identity_events) with the O-011 automation-rules engine
persistence (ADR-0011). Two tables:

  automation_rules       — TENANT-SCOPED (RLS, mirrors ingest_events/0001 and
                          identity_events/0007). One row per tenant-defined rule: react
                          to `trigger_event_type` (optionally filtered by
                          `trigger_source_product`), match a flat scalar-equality
                          `trigger_conditions` dict against the payload, and on a match
                          trigger exactly one closed `action_type` ('redistribute_policy'
                          in v1). App-role INSERT/SELECT/UPDATE/DELETE (RLS-scoped);
                          UNIQUE(tenant_id, name) makes rule names unique per tenant.
  automation_executions  — GLOBAL tamper-evident hash chain (mirrors
                          distribution_audit_log/0002: privileged writes, RLS scopes
                          SELECT to the row's own tenant_id — UNLIKE relay_audit_log/
                          identity_audit_log, which carry no RLS at all, because this
                          table IS genuinely tenant-relevant audit data a tenant reads
                          back via GET /v1/automation/executions). Append-only (deny
                          triggers). UNIQUE(rule_id, triggering_event_id) is the
                          idempotency dedup gate for a retried/duplicate background-task
                          schedule of the same accepted ingest event.

The orchestrator_app role already exists (created in 0001). automation_rules gets the
SAME tenant_isolation RLS policy shape as ingest_events (ENABLE + FORCE + NULLIF
predicate); automation_executions gets the ingest_audit_log/distribution_audit_log RLS
shape (SELECT scoped by NULLIF, INSERT permissive/privileged-only, UPDATE/DELETE denied).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_automation_engine"
down_revision: Union[str, None] = "0007_identity_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# v1 supports exactly ONE action type. Adding a second is explicit future work (ADR-0011
# Honesty boundaries / Out of scope) — this CHECK constraint keeps that closed at the DB
# layer, not merely at the app layer.
_ACTION_TYPES = "'redistribute_policy'"
# The source_products already used by the ingest/relay/identity seams (mirrors
# KNOWN_IDENTITY_SOURCE_PRODUCTS in config.py) — trigger_source_product is an OPTIONAL
# filter, so NULL (no filter) is also permitted.
_SOURCE_PRODUCTS = "'sentinel','delta','rendly'"
_DISPOSITIONS = "'executed','failed'"
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. automation_rules — tenant-scoped (RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "automation_rules",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("trigger_event_type", sa.String(64), nullable=False),
        sa.Column("trigger_source_product", sa.String(32), nullable=True),
        sa.Column(
            "trigger_conditions",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("action_config", postgresql.JSONB, nullable=False),
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
        sa.CheckConstraint(f"action_type IN ({_ACTION_TYPES})", name="ck_ar_action_type"),
        sa.CheckConstraint(
            f"trigger_source_product IS NULL OR trigger_source_product IN ({_SOURCE_PRODUCTS})",
            name="ck_ar_trigger_source_product",
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_ar_tenant_name"),
    )
    op.create_index("ix_ar_tenant_id", "automation_rules", ["tenant_id"])
    op.create_index(
        "ix_ar_tenant_event_type", "automation_rules", ["tenant_id", "trigger_event_type"]
    )

    # ------------------------------------------------------------------ #
    # 2. automation_executions — GLOBAL hash chain (privileged writes, RLS-scoped SELECT).
    # ------------------------------------------------------------------ #
    op.create_table(
        "automation_executions",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("triggering_event_id", sa.String(64), nullable=False),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        # opt-in-when-present (folded into the hash iff not None). Short code only.
        sa.Column("error_reason", sa.String(64), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"action_type IN ({_ACTION_TYPES})", name="ck_ae_action_type"),
        sa.CheckConstraint(f"disposition IN ({_DISPOSITIONS})", name="ck_ae_disposition"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_ae_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_ae_row_hash_len"),
        sa.UniqueConstraint("rule_id", "triggering_event_id", name="uq_ae_rule_triggering_event"),
    )
    op.create_index("ix_ae_tenant_id", "automation_executions", ["tenant_id"])
    op.create_index("ix_ae_rule_id", "automation_executions", ["rule_id"])

    # ------------------------------------------------------------------ #
    # 3. Append-only enforcement on automation_executions (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_automation_execution_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'automation_executions is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ae_deny_update BEFORE UPDATE ON automation_executions "
            "FOR EACH ROW EXECUTE FUNCTION deny_automation_execution_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ae_deny_delete BEFORE DELETE ON automation_executions "
            "FOR EACH ROW EXECUTE FUNCTION deny_automation_execution_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 4. RLS on automation_rules (ENABLE + FORCE + NULLIF policy, mirrors 0001/0007).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("ALTER TABLE automation_rules ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE automation_rules FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            "CREATE POLICY tenant_isolation ON automation_rules "
            f"USING ({_NULLIF_PREDICATE}) WITH CHECK ({_NULLIF_PREDICATE})"
        )
    )

    # ------------------------------------------------------------------ #
    # 5. RLS on automation_executions: SELECT scoped (NULLIF); INSERT permissive
    #    (privileged-only writes); UPDATE/DELETE denied (belt-and-suspenders with the
    #    triggers). Mirrors ingest_audit_log (0001) / distribution_audit_log (0002) —
    #    UNLIKE relay_audit_log/identity_audit_log, which carry NO RLS at all, because
    #    this table is genuinely tenant-relevant audit data a tenant reads back.
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("ALTER TABLE automation_executions ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE automation_executions FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            "CREATE POLICY ae_select ON automation_executions FOR SELECT "
            f"USING ({_NULLIF_PREDICATE})"
        )
    )
    conn.execute(
        sa.text("CREATE POLICY ae_insert ON automation_executions FOR INSERT WITH CHECK (true)")
    )
    conn.execute(
        sa.text("CREATE POLICY ae_deny_update ON automation_executions FOR UPDATE USING (false)")
    )
    conn.execute(
        sa.text("CREATE POLICY ae_deny_delete ON automation_executions FOR DELETE USING (false)")
    )

    # ------------------------------------------------------------------ #
    # 6. Minimal DML grants.
    #    automation_rules: SELECT, INSERT, UPDATE, DELETE (full tenant-scoped CRUD).
    #    automation_executions: SELECT only (inserts run on the privileged session).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text("GRANT SELECT, INSERT, UPDATE, DELETE ON automation_rules TO orchestrator_app")
    )
    conn.execute(sa.text("GRANT SELECT ON automation_executions TO orchestrator_app"))

    # automation_executions uses a bigserial PK -> grant USAGE on its sequence.
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('automation_executions', 'sequence_number')
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

    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('automation_executions', 'sequence_number')
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

    conn.execute(sa.text("DROP POLICY IF EXISTS ae_deny_delete ON automation_executions"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ae_deny_update ON automation_executions"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ae_insert ON automation_executions"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ae_select ON automation_executions"))
    conn.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON automation_rules"))

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ae_deny_update ON automation_executions"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ae_deny_delete ON automation_executions"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_automation_execution_modification()"))

    op.drop_table("automation_executions")
    op.drop_table("automation_rules")
