"""agent_messages + agent_messaging_audit_log + agent_state + agent_state_audit_log (O-012).

Revision ID: 0009_agent_messaging
Revises: 0008_automation_engine
Create Date: 2026-07-08

Extends the live head (0008_automation_engine) with the O-012 agent-messaging + shared
state-store persistence (ADR-0012). Two independent seams, four tables:

  agent_messages            — TENANT-SCOPED (RLS, mirrors ingest_events/0001 and
                             automation_rules/0008). One row per sent message: sender +
                             recipient F-002 stable-ID triples (both under the SAME
                             tenant_id column — no cross-tenant messaging is structurally
                             possible), an opaque JSONB `body` (never inspected by the
                             Orchestrator), and UNIQUE(tenant_id, idempotency_key) as the
                             sender's own dedup gate. sequence_number is the GLOBAL insert
                             order and doubles as the inbox pagination cursor directly.
  agent_messaging_audit_log — GLOBAL tamper-evident hash chain (mirrors
                             automation_executions/0008: privileged writes, RLS scopes
                             SELECT to the row's own tenant_id). Records every send
                             ATTEMPT — both 'sent' and 'deduped' get a chain link (O-003
                             ingest_audit_log semantics, NOT automation_executions'
                             "only genuine executions" semantics — see ADR-0012).
  agent_state               — TENANT-SCOPED (RLS). One row per (tenant_id, state_key),
                             UNIQUE(tenant_id, state_key). `version` is the
                             optimistic-concurrency token, incremented by exactly 1 on
                             every successful write.
  agent_state_audit_log     — GLOBAL tamper-evident hash chain (mirrors
                             automation_executions' "only the meaningful outcome"
                             semantics — a version-CONFLICT rejection produces NO row).

The orchestrator_app role already exists (created in 0001). Both tenant-scoped tables get
the SAME tenant_isolation RLS policy shape as ingest_events/automation_rules (ENABLE +
FORCE + NULLIF predicate); both audit-chain tables get the automation_executions RLS shape
(SELECT scoped by NULLIF, INSERT permissive/privileged-only, UPDATE/DELETE denied) plus
BEFORE UPDATE/DELETE deny triggers (append-only, mirrors 0008 exactly).

Following O-011's precedent: a DB-level CHECK constraint enforcing agent_messages.body /
agent_state.state_value are JSON OBJECTS (`jsonb_typeof(...) = 'object'`) is added — simpler
than O-011's scalar-only `jsonb_path_exists` constraint since these fields hold arbitrary
structured payloads, not a flat scalar-only map.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_agent_messaging"
down_revision: Union[str, None] = "0008_automation_engine"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_MESSAGING_DISPOSITIONS = "'sent','deduped'"
_STATE_DISPOSITIONS = "'created','updated'"
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. agent_messages — tenant-scoped (RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "agent_messages",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("sender_team_id", sa.String(64), nullable=False),
        sa.Column("sender_project_id", sa.String(64), nullable=False),
        sa.Column("sender_agent_id", sa.String(64), nullable=False),
        sa.Column("recipient_team_id", sa.String(64), nullable=False),
        sa.Column("recipient_project_id", sa.String(64), nullable=False),
        sa.Column("recipient_agent_id", sa.String(64), nullable=False),
        sa.Column("message_type", sa.String(64), nullable=False),
        sa.Column("body", postgresql.JSONB, nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("jsonb_typeof(body) = 'object'", name="ck_am_body_is_object"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_am_tenant_idempotency"),
    )
    op.create_index(
        "ix_am_inbox",
        "agent_messages",
        [
            "tenant_id",
            "recipient_team_id",
            "recipient_project_id",
            "recipient_agent_id",
            "sequence_number",
        ],
    )

    # ------------------------------------------------------------------ #
    # 2. agent_messaging_audit_log — GLOBAL hash chain (privileged writes, RLS-scoped SELECT).
    # ------------------------------------------------------------------ #
    op.create_table(
        "agent_messaging_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("sender_agent_id", sa.String(64), nullable=False),
        sa.Column("recipient_agent_id", sa.String(64), nullable=False),
        sa.Column("message_type", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            f"disposition IN ({_MESSAGING_DISPOSITIONS})", name="ck_ama_disposition"
        ),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_ama_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_ama_row_hash_len"),
    )
    op.create_index("ix_ama_tenant_id", "agent_messaging_audit_log", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 3. agent_state — tenant-scoped (RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "agent_state",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("state_key", sa.String(256), nullable=False),
        sa.Column("state_value", postgresql.JSONB, nullable=False),
        sa.Column("version", sa.BigInteger, nullable=False, server_default=sa.text("1")),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("updated_by_agent_id", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(state_value) = 'object'", name="ck_as_state_value_is_object"
        ),
        sa.CheckConstraint("version >= 1", name="ck_as_version_positive"),
        sa.UniqueConstraint("tenant_id", "state_key", name="uq_as_tenant_state_key"),
    )
    op.create_index("ix_as_tenant_id", "agent_state", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 4. agent_state_audit_log — GLOBAL hash chain (privileged writes, RLS-scoped SELECT).
    # ------------------------------------------------------------------ #
    op.create_table(
        "agent_state_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("state_key", sa.String(256), nullable=False),
        sa.Column("version", sa.BigInteger, nullable=False),
        sa.Column("updated_by_agent_id", sa.String(64), nullable=True),
        sa.Column("disposition", sa.String(16), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"disposition IN ({_STATE_DISPOSITIONS})", name="ck_asa_disposition"),
        sa.CheckConstraint("version >= 1", name="ck_asa_version_positive"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_asa_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_asa_row_hash_len"),
    )
    op.create_index("ix_asa_tenant_id", "agent_state_audit_log", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 5. Append-only enforcement (BEFORE UPDATE/DELETE) on both audit-chain tables.
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_agent_messaging_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'agent_messaging_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ama_deny_update BEFORE UPDATE ON agent_messaging_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_agent_messaging_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ama_deny_delete BEFORE DELETE ON agent_messaging_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_agent_messaging_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_agent_state_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'agent_state_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_asa_deny_update BEFORE UPDATE ON agent_state_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_agent_state_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_asa_deny_delete BEFORE DELETE ON agent_state_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_agent_state_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 6. RLS on agent_messages + agent_state (ENABLE + FORCE + NULLIF policy).
    # ------------------------------------------------------------------ #
    for table in ("agent_messages", "agent_state"):
        conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        conn.execute(
            sa.text(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING ({_NULLIF_PREDICATE}) WITH CHECK ({_NULLIF_PREDICATE})"
            )
        )

    # ------------------------------------------------------------------ #
    # 7. RLS on both audit-chain tables: SELECT scoped (NULLIF); INSERT permissive
    #    (privileged-only writes); UPDATE/DELETE denied (belt-and-suspenders with the
    #    triggers). Mirrors automation_executions (0008) — UNLIKE relay_audit_log/
    #    identity_audit_log, which carry NO RLS at all — because both new chains are
    #    genuinely tenant-relevant audit data.
    # ------------------------------------------------------------------ #
    for table, prefix in (
        ("agent_messaging_audit_log", "ama"),
        ("agent_state_audit_log", "asa"),
    ):
        conn.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        conn.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        conn.execute(
            sa.text(
                f"CREATE POLICY {prefix}_select ON {table} FOR SELECT USING ({_NULLIF_PREDICATE})"
            )
        )
        conn.execute(
            sa.text(f"CREATE POLICY {prefix}_insert ON {table} FOR INSERT WITH CHECK (true)")
        )
        conn.execute(
            sa.text(f"CREATE POLICY {prefix}_deny_update ON {table} FOR UPDATE USING (false)")
        )
        conn.execute(
            sa.text(f"CREATE POLICY {prefix}_deny_delete ON {table} FOR DELETE USING (false)")
        )

    # ------------------------------------------------------------------ #
    # 8. Minimal DML grants.
    #    agent_messages: SELECT, INSERT only (no UPDATE/DELETE — messages are immutable
    #    once sent; there is no edit/delete seam in v1).
    #    agent_state: SELECT, INSERT, UPDATE (no DELETE — no DELETE endpoint in v1).
    #    Both audit logs: SELECT only (inserts run on the privileged session).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("GRANT SELECT, INSERT ON agent_messages TO orchestrator_app"))
    conn.execute(sa.text("GRANT SELECT, INSERT, UPDATE ON agent_state TO orchestrator_app"))
    conn.execute(sa.text("GRANT SELECT ON agent_messaging_audit_log TO orchestrator_app"))
    conn.execute(sa.text("GRANT SELECT ON agent_state_audit_log TO orchestrator_app"))

    # Bigserial PKs -> grant USAGE on their sequences.
    for table, column in (
        ("agent_messages", "sequence_number"),
        ("agent_messaging_audit_log", "sequence_number"),
        ("agent_state", "id"),
        ("agent_state_audit_log", "sequence_number"),
    ):
        conn.execute(
            sa.text(
                f"""
                DO $$
                DECLARE seq_name TEXT;
                BEGIN
                    SELECT pg_get_serial_sequence('{table}', '{column}') INTO seq_name;
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

    for table, column in (
        ("agent_messages", "sequence_number"),
        ("agent_messaging_audit_log", "sequence_number"),
        ("agent_state", "id"),
        ("agent_state_audit_log", "sequence_number"),
    ):
        conn.execute(
            sa.text(
                f"""
                DO $$
                DECLARE seq_name TEXT;
                BEGIN
                    SELECT pg_get_serial_sequence('{table}', '{column}') INTO seq_name;
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

    for table in ("agent_messaging_audit_log", "agent_state_audit_log"):
        conn.execute(sa.text(f"DROP POLICY IF EXISTS {table[:3]}_deny_delete ON {table}"))
        conn.execute(sa.text(f"DROP POLICY IF EXISTS {table[:3]}_deny_update ON {table}"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ama_insert ON agent_messaging_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ama_select ON agent_messaging_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS asa_insert ON agent_state_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS asa_select ON agent_state_audit_log"))

    for table in ("agent_messages", "agent_state"):
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_asa_deny_update ON agent_state_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_asa_deny_delete ON agent_state_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_agent_state_audit_modification()"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ama_deny_update ON agent_messaging_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ama_deny_delete ON agent_messaging_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_agent_messaging_audit_modification()"))

    op.drop_table("agent_state_audit_log")
    op.drop_table("agent_state")
    op.drop_table("agent_messaging_audit_log")
    op.drop_table("agent_messages")
