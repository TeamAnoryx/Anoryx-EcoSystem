"""safety_events + safety_audit_log — cross-product safety-event visibility (X-004).

Revision ID: 0012_safety_events
Revises: 0011_command_center
Create Date: 2026-07-10

Extends the live head (0011_command_center) with the X-004 cross-product safety-event
visibility seam. Two tables, mirroring 0007_identity_events' shape exactly:

  safety_events      — TENANT-SCOPED (RLS, mirrors identity_events/0007). One normalized
                      "a local safety inspection produced a non-pass outcome" record per
                      (source_product, idempotency_key): Sentinel, Delta, or Rendly each
                      push ONE record after their OWN in-product content inspection
                      fires. App-role INSERT + SELECT (RLS-scoped); UNIQUE(source_product,
                      idempotency_key) makes ingestion idempotent (a retried push is a
                      no-op, not a duplicate row).
  safety_audit_log   — GLOBAL tamper-evident hash chain (mirrors identity_audit_log/
                      relay_audit_log/sentinel_registry_audit_log). Append-only (deny
                      triggers). Privileged writes only; NO RLS — cross-tenant fleet
                      infrastructure, not tenant data, same precedent as the O-005
                      registry, O-009 relay, and O-010 identity chains. Records BOTH a
                      fresh accept and an idempotent duplicate (disposition
                      'accepted' | 'duplicate') so every ingest ATTEMPT is
                      tamper-evidently recorded, not only first-time accepts.

METADATA ONLY: no message/prompt content is ever persisted here — only category/outcome/
target (opaque id)/tenant/timestamps, exactly as the contract bounds it.

The orchestrator_app role already exists (created in 0001). safety_events gets the
SAME tenant_isolation RLS policy shape as identity_events (ENABLE + FORCE + NULLIF
predicate) plus a cursor index mirroring ix_ide_tenant_seq (0007); the audit chain grants
orchestrator_app NOTHING (least privilege, mirrors 0004/0006/0007).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_safety_events"
down_revision: Union[str, None] = "0011_command_center"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SOURCE_PRODUCTS = "'sentinel','delta','rendly'"
_CATEGORIES = "'pii','injection','secret'"
_OUTCOMES = "'block'"
_DISPOSITIONS = "'accepted','duplicate'"
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. safety_events — tenant-scoped (RLS), idempotent ingest.
    # ------------------------------------------------------------------ #
    op.create_table(
        "safety_events",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("source_product", sa.String(16), nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
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
        sa.CheckConstraint(
            f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_safe_source_product"
        ),
        sa.CheckConstraint(f"category IN ({_CATEGORIES})", name="ck_safe_category"),
        sa.CheckConstraint(f"outcome IN ({_OUTCOMES})", name="ck_safe_outcome"),
        sa.UniqueConstraint("source_product", "idempotency_key", name="uq_safe_source_idempotency"),
    )
    op.create_index("ix_safe_tenant_seq", "safety_events", ["tenant_id", "sequence_number"])
    op.create_index("ix_safe_source_product", "safety_events", ["source_product"])

    # ------------------------------------------------------------------ #
    # 2. safety_audit_log — GLOBAL hash chain (privileged writes only, no RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "safety_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("source_product", sa.String(16), nullable=False),
        sa.Column("category", sa.String(16), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
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
            f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_safal_source_product"
        ),
        sa.CheckConstraint(f"category IN ({_CATEGORIES})", name="ck_safal_category"),
        sa.CheckConstraint(f"outcome IN ({_OUTCOMES})", name="ck_safal_outcome"),
        sa.CheckConstraint(f"disposition IN ({_DISPOSITIONS})", name="ck_safal_disposition"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_safal_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_safal_row_hash_len"),
    )
    op.create_index("ix_safal_tenant_id", "safety_audit_log", ["tenant_id"])

    # ------------------------------------------------------------------ #
    # 3. RLS on safety_events (ENABLE + FORCE + NULLIF policy, mirrors 0007).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("ALTER TABLE safety_events ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text("ALTER TABLE safety_events FORCE ROW LEVEL SECURITY"))
    conn.execute(
        sa.text(
            "CREATE POLICY tenant_isolation ON safety_events "
            f"USING ({_NULLIF_PREDICATE}) WITH CHECK ({_NULLIF_PREDICATE})"
        )
    )

    # ------------------------------------------------------------------ #
    # 4. Append-only enforcement on safety_audit_log (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_safety_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'safety_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_safal_deny_update BEFORE UPDATE ON safety_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_safety_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_safal_deny_delete BEFORE DELETE ON safety_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_safety_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 5. Minimal DML grants. safety_events: SELECT + INSERT (RLS-scoped tenant writes).
    #    safety_audit_log: NOTHING (privileged-only chain, mirrors 0004/0006/0007).
    # ------------------------------------------------------------------ #
    conn.execute(sa.text("GRANT SELECT, INSERT ON safety_events TO orchestrator_app"))
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE seq_name TEXT;
            BEGIN
                SELECT pg_get_serial_sequence('safety_events', 'sequence_number') INTO seq_name;
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

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_safal_deny_update ON safety_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_safal_deny_delete ON safety_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_safety_audit_modification()"))
    conn.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON safety_events"))

    op.drop_table("safety_audit_log")
    op.drop_table("safety_events")
