"""Orchestrator ingest baseline: events store, global hash-chained audit, DLQ, outbox.

Revision ID: 0001
Revises:
Create Date: 2026-06-26

The Orchestrator's FIRST migration (O-003, ADR-0003). Ports Sentinel's F-003 hash-chain +
F-003b two-role RLS patterns into the Orchestrator's own database.

Four tables:
  ingest_events      — tenant-scoped (RLS). Dedup (UNIQUE idempotency_key) + metadata +
                       full payload + source_sequence for replay. App-role writes.
  ingest_audit_log   — GLOBAL tamper-evident hash chain. Append-only (deny-triggers).
                       Privileged writes only; RLS scopes SELECT. (rule 7)
  dead_letter_queue  — tenant-scoped (RLS, closes O-002 LOW-2). The failure-envelope.
                       Privileged writes (tenant_id may be NULL for payload-invalid rows,
                       which the app role's WITH CHECK would reject); RLS scopes reads.
  forward_outbox     — tenant-scoped (RLS). Forward-INTENT only (O-005 consumes it).

Roles:
  orchestrator_app   — LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE. No password
                       in SQL (Vault out-of-band; local/CI via ALTER ROLE). Minimal DML.

Strict fail-closed RLS predicate (ADR-0005 lineage):
  tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
unsatisfiable when the GUC is unset/empty → zero rows, never a widen.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SOURCE_PRODUCTS = "'sentinel','orchestrator','delta','rendly'"
_DLQ_REASONS = (
    "'unknown_schema_version','payload_schema_invalid','source_identity_mismatch',"
    "'idempotency_conflict','max_attempts_exceeded'"
)
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# Tenant-scoped tables that get the standard tenant_isolation policy (USING + WITH CHECK).
_TENANT_TABLES = ["ingest_events", "dead_letter_queue", "forward_outbox"]


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. orchestrator_app role (idempotent, NO password in SQL).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'orchestrator_app') THEN
                    CREATE ROLE orchestrator_app
                        LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
                END IF;
            END
            $$;
            """
        )
    )

    # ------------------------------------------------------------------ #
    # 2a. ingest_events — dedup + metadata + replay-source store.
    # ------------------------------------------------------------------ #
    op.create_table(
        "ingest_events",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("envelope_id", sa.String(64), nullable=False, unique=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("source_product", sa.String(32), nullable=False),
        sa.Column("source_sequence", sa.BigInteger, nullable=False),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("occurred_at", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("causation_id", sa.String(128), nullable=True),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("event_timestamp", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column(
            "received_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("schema_version >= 1", name="ck_ie_schema_version"),
        sa.CheckConstraint(f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_ie_source_product"),
        sa.CheckConstraint("source_sequence >= 0", name="ck_ie_source_sequence"),
        sa.CheckConstraint("length(content_hash) = 64", name="ck_ie_content_hash_len"),
    )
    op.create_index("ix_ie_tenant_id", "ingest_events", ["tenant_id"])
    op.create_index("ix_ie_event_type", "ingest_events", ["event_type"])
    op.create_index("ix_ie_source_seq", "ingest_events", ["source_product", "source_sequence"])

    # ------------------------------------------------------------------ #
    # 2b. ingest_audit_log — GLOBAL hash chain (privileged writes).
    # ------------------------------------------------------------------ #
    op.create_table(
        "ingest_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        # Payload-derived attribution — NULLABLE (a dead_lettered link for a payload-
        # invalid envelope has no trustworthy payload IDs). The ck_ial_accepted_attribution
        # CHECK below requires them non-null for accepted links.
        sa.Column("event_id", sa.String(64), nullable=True),
        sa.Column("event_timestamp", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("tenant_id", sa.String(64), nullable=True),
        sa.Column("team_id", sa.String(64), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        sa.Column("agent_id", sa.String(64), nullable=True),
        # Envelope-derived (always present — the envelope passed structural validation).
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("envelope_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("source_product", sa.String(32), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        sa.Column("dlq_reason", sa.String(32), nullable=True),
        sa.Column("dlq_id", sa.String(64), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.CheckConstraint(
            "disposition IN ('accepted','deduped','dead_lettered')",
            name="ck_ial_disposition",
        ),
        # Accepted links MUST carry full F-002 attribution (the four stable IDs + the
        # event identity/time). dead_lettered links may omit payload-derived fields.
        sa.CheckConstraint(
            "disposition <> 'accepted' OR ("
            "event_id IS NOT NULL AND event_timestamp IS NOT NULL AND "
            "request_id IS NOT NULL AND tenant_id IS NOT NULL AND team_id IS NOT NULL AND "
            "project_id IS NOT NULL AND agent_id IS NOT NULL)",
            name="ck_ial_accepted_attribution",
        ),
        sa.CheckConstraint(f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_ial_source_product"),
        sa.CheckConstraint(
            f"dlq_reason IS NULL OR dlq_reason IN ({_DLQ_REASONS})",
            name="ck_ial_dlq_reason",
        ),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_ial_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_ial_row_hash_len"),
    )
    op.create_index("ix_ial_tenant_id", "ingest_audit_log", ["tenant_id"])
    op.create_index("ix_ial_idempotency_key", "ingest_audit_log", ["idempotency_key"])
    op.create_index("ix_ial_sequence_number", "ingest_audit_log", ["sequence_number"])

    # ------------------------------------------------------------------ #
    # 2c. dead_letter_queue — failure-envelope store (privileged writes).
    # ------------------------------------------------------------------ #
    op.create_table(
        "dead_letter_queue",
        sa.Column("dlq_id", sa.String(64), primary_key=True),
        sa.Column("original_envelope", postgresql.JSONB, nullable=False),
        sa.Column("reason", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default=sa.text("1")),
        sa.Column("first_failed_at", sa.String(64), nullable=False),
        sa.Column("last_failed_at", sa.String(64), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("source_product", sa.String(32), nullable=False),
        sa.Column("source_sequence", sa.BigInteger, nullable=True),
        sa.Column("tenant_id", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"reason IN ({_DLQ_REASONS})", name="ck_dlq_reason"),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 1000", name="ck_dlq_attempt_count"
        ),
        sa.CheckConstraint(f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_dlq_source_product"),
    )
    op.create_index("ix_dlq_tenant_id", "dead_letter_queue", ["tenant_id"])
    op.create_index("ix_dlq_reason", "dead_letter_queue", ["reason"])

    # ------------------------------------------------------------------ #
    # 2d. forward_outbox — forward-INTENT only.
    # ------------------------------------------------------------------ #
    op.create_table(
        "forward_outbox",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'pending'")),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("status IN ('pending')", name="ck_fo_status"),
    )
    op.create_index("ix_fo_tenant_id", "forward_outbox", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 3. Append-only enforcement on ingest_audit_log (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_ingest_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'ingest_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ial_deny_update BEFORE UPDATE ON ingest_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_ingest_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ial_deny_delete BEFORE DELETE ON ingest_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_ingest_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 4. RLS on the three tenant-scoped tables (ENABLE + FORCE + NULLIF policy).
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

    # ingest_audit_log RLS: SELECT scoped (NULLIF); INSERT permissive (privileged-only
    # writes); UPDATE/DELETE denied (USING false — belt-and-suspenders with the triggers).
    conn.execute(sa.text("ALTER TABLE ingest_audit_log ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE ingest_audit_log FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            f"CREATE POLICY ial_select ON ingest_audit_log FOR SELECT "
            f"USING ({_NULLIF_PREDICATE})"
        )
    )
    conn.execute(
        sa.text("CREATE POLICY ial_insert ON ingest_audit_log FOR INSERT WITH CHECK (true)")
    )
    conn.execute(
        sa.text("CREATE POLICY ial_deny_update ON ingest_audit_log FOR UPDATE USING (false)")
    )
    conn.execute(
        sa.text("CREATE POLICY ial_deny_delete ON ingest_audit_log FOR DELETE USING (false)")
    )

    # ------------------------------------------------------------------ #
    # 5. Minimal DML grants to orchestrator_app.
    #    SELECT on all four (tenant reads, RLS-scoped).
    #    INSERT on ingest_events + forward_outbox (the accept tenant writes).
    #    NO INSERT/UPDATE/DELETE on ingest_audit_log (chain = privileged).
    #    NO INSERT on dead_letter_queue (DLQ writes = privileged; reads RLS-scoped).
    #    No DDL, no BYPASSRLS, no superuser.
    # ------------------------------------------------------------------ #
    for table in ("ingest_events", "ingest_audit_log", "dead_letter_queue", "forward_outbox"):
        conn.execute(sa.text(f"GRANT SELECT ON {table} TO orchestrator_app"))
    conn.execute(sa.text("GRANT INSERT ON ingest_events TO orchestrator_app"))
    conn.execute(sa.text("GRANT INSERT ON forward_outbox TO orchestrator_app"))

    # The app role inserts into ingest_events (bigserial) → needs USAGE on its sequence.
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('ingest_events', 'sequence_number') INTO seq_name;
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

    # Revoke sequence grant.
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('ingest_events', 'sequence_number') INTO seq_name;
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

    # Drop policies, triggers, then tables. (Dropping a table drops its policies too, but
    # be explicit for clarity / partial-failure recovery.)
    conn.execute(sa.text("DROP POLICY IF EXISTS ial_deny_delete ON ingest_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ial_deny_update ON ingest_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ial_insert ON ingest_audit_log"))
    conn.execute(sa.text("DROP POLICY IF EXISTS ial_select ON ingest_audit_log"))
    for table in _TENANT_TABLES:
        conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ial_deny_update ON ingest_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ial_deny_delete ON ingest_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_ingest_audit_modification()"))

    op.drop_table("forward_outbox")
    op.drop_table("dead_letter_queue")
    op.drop_table("ingest_audit_log")
    op.drop_table("ingest_events")

    # Drop orchestrator_app only if it owns no objects (never destructive to data).
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE owned_count INT;
            BEGIN
                SELECT COUNT(*) INTO owned_count
                FROM pg_class c JOIN pg_roles r ON c.relowner = r.oid
                WHERE r.rolname = 'orchestrator_app';
                IF owned_count = 0 THEN
                    DROP ROLE IF EXISTS orchestrator_app;
                ELSE
                    RAISE NOTICE
                        'orchestrator_app owns % object(s); role not dropped.',
                        owned_count;
                END IF;
            END
            $$;
            """
        )
    )
