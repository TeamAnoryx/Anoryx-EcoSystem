"""identity_events + identity_audit_log — cross-product identity/access correlation (O-010).

Revision ID: 0007_identity_events
Revises: 0006_relay_audit_log
Create Date: 2026-07-08

Extends the live head (0006_relay_audit_log) with the O-010 governed identity-event
correlation seam (ADR-0010). Two tables:

  identity_events      — TENANT-SCOPED (RLS, mirrors ingest_events/0001). One normalized
                        "who accessed what, where" record per (source_product,
                        idempotency_key): a principal in Sentinel/Delta/Rendly took an
                        action, at a tenant, optionally against a target. App-role
                        INSERT + SELECT (RLS-scoped); UNIQUE(source_product,
                        idempotency_key) makes ingestion idempotent (a retried push is a
                        no-op, not a duplicate row).
  identity_audit_log   — GLOBAL tamper-evident hash chain (mirrors relay_audit_log/
                        sentinel_registry_audit_log). Append-only (deny triggers).
                        Privileged writes only; NO RLS — cross-tenant fleet
                        infrastructure, not tenant data, same precedent as the O-005
                        registry and O-009 relay chains. Records BOTH a fresh accept and
                        an idempotent duplicate (disposition 'accepted' | 'duplicate') so
                        every ingest ATTEMPT is tamper-evidently recorded, not only
                        first-time accepts.

The orchestrator_app role already exists (created in 0001). identity_events gets the
SAME tenant_isolation RLS policy shape as ingest_events (ENABLE + FORCE + NULLIF
predicate) plus a cursor index mirroring ix_ingest_events_tenant_seq (0005); the audit
chain grants orchestrator_app NOTHING (least privilege, mirrors 0004/0006).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_identity_events"
down_revision: Union[str, None] = "0006_relay_audit_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SOURCE_PRODUCTS = "'sentinel','delta','rendly'"
_PRINCIPAL_TYPES = "'operator','tenant_user','service_account','peer_credential'"
_DISPOSITIONS = "'accepted','duplicate'"
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. identity_events — tenant-scoped (RLS), idempotent ingest.
    # ------------------------------------------------------------------ #
    op.create_table(
        "identity_events",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("source_product", sa.String(16), nullable=False),
        sa.Column("principal_type", sa.String(32), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        # opt-in-when-present at the application layer (nullable here; NULL == absent).
        sa.Column("target", sa.String(256), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("occurred_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "received_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_ide_source_product"),
        sa.CheckConstraint(f"principal_type IN ({_PRINCIPAL_TYPES})", name="ck_ide_principal_type"),
        sa.UniqueConstraint("source_product", "idempotency_key", name="uq_ide_source_idempotency"),
    )
    op.create_index("ix_ide_tenant_seq", "identity_events", ["tenant_id", "sequence_number"])
    op.create_index("ix_ide_source_product", "identity_events", ["source_product"])

    # ------------------------------------------------------------------ #
    # 2. identity_audit_log — GLOBAL hash chain (privileged writes only, no RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "identity_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("source_product", sa.String(16), nullable=False),
        sa.Column("principal_type", sa.String(32), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        # opt-in-when-present (folded into the hash iff not None).
        sa.Column("target", sa.String(256), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_ial2_source_product"
        ),
        sa.CheckConstraint(
            f"principal_type IN ({_PRINCIPAL_TYPES})", name="ck_ial2_principal_type"
        ),
        sa.CheckConstraint(f"disposition IN ({_DISPOSITIONS})", name="ck_ial2_disposition"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_ial2_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_ial2_row_hash_len"),
    )
    op.create_index("ix_ial2_tenant_id", "identity_audit_log", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 3. RLS on identity_events (ENABLE + FORCE + NULLIF policy, mirrors 0001).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("ALTER TABLE identity_events ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE identity_events FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            "CREATE POLICY tenant_isolation ON identity_events "
            f"USING ({_NULLIF_PREDICATE}) WITH CHECK ({_NULLIF_PREDICATE})"
        )
    )

    # ------------------------------------------------------------------ #
    # 4. Append-only enforcement on identity_audit_log (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_identity_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'identity_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ial2_deny_update BEFORE UPDATE ON identity_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_identity_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ial2_deny_delete BEFORE DELETE ON identity_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_identity_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 5. Minimal DML grants. identity_events: SELECT + INSERT (RLS-scoped tenant writes).
    #    identity_audit_log: NOTHING (privileged-only chain, mirrors 0004/0006/0009).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("GRANT SELECT, INSERT ON identity_events TO orchestrator_app"))
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('identity_events', 'sequence_number') INTO seq_name;
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

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ial2_deny_update ON identity_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ial2_deny_delete ON identity_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_identity_audit_modification()"))
    conn.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON identity_events"))

    op.drop_table("identity_audit_log")
    op.drop_table("identity_events")
