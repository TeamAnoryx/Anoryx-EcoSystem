"""relay_audit_log — tamper-evident GLOBAL relay-dispatch chain (O-009, ADR-0009).

Revision ID: 0006_relay_audit_log
Revises: 0005_tenant_principal_and_reads
Create Date: 2026-07-08

Extends the live head (0005_tenant_principal_and_reads) with the O-009 governed-relay
persistence. One table, mirroring sentinel_registry_audit_log / distribution_audit_log
exactly:

  relay_audit_log   — GLOBAL tamper-evident relay-dispatch hash chain. Records every dispatch
                      attempt whether it was actually forwarded to Sentinel and answered
                      (disposition='forwarded', any status_code Sentinel returned), blocked
                      before any outbound call (unknown/disabled/unhealthy target, or an
                      endpoint that fails SSRF re-validation), or failed at the transport layer
                      (disposition='failed', a connect/timeout error). Append-only (deny
                      triggers). Privileged writes only; NO RLS — like the O-005 registry, this
                      is cross-tenant infrastructure (a fleet-wide relay chain), not tenant data;
                      tenant_id is a plain attribution column, not an RLS dimension.

The orchestrator_app role already exists (created in 0001). This migration grants it nothing —
the relay audit chain is accessed only via the privileged session (least privilege, mirrors the
sentinel_registry_audit_log / distribution_audit_log precedent).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_relay_audit_log"
down_revision: Union[str, None] = "0005_tenant_principal_and_reads"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SOURCE_PRODUCTS = "'delta','rendly'"
_DISPOSITIONS = "'forwarded','blocked','failed'"


def upgrade() -> None:
    conn = op.get_bind()

    # ------------------------------------------------------------------ #
    # 1. relay_audit_log — GLOBAL hash chain (privileged writes only, no RLS).
    # ------------------------------------------------------------------ #
    op.create_table(
        "relay_audit_log",
        sa.Column("sequence_number", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("source_product", sa.String(16), nullable=False),
        sa.Column("sentinel_id", sa.String(128), nullable=False),
        sa.Column("target_path", sa.String(256), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        # opt-in-when-present (folded into the hash iff not None).
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("error_reason", sa.Text, nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(f"source_product IN ({_SOURCE_PRODUCTS})", name="ck_ral_source_product"),
        sa.CheckConstraint(f"disposition IN ({_DISPOSITIONS})", name="ck_ral_disposition"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_ral_prev_hash_len"),
        sa.CheckConstraint("length(row_hash) = 64", name="ck_ral_row_hash_len"),
    )
    op.create_index("ix_ral_tenant_id", "relay_audit_log", ["tenant_id"])
    op.create_index("ix_ral_sentinel_id", "relay_audit_log", ["sentinel_id"])

    # ------------------------------------------------------------------ #
    # 2. Append-only enforcement on relay_audit_log (BEFORE UPDATE/DELETE).
    # ------------------------------------------------------------------ #
    conn.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION deny_relay_audit_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'relay_audit_log is append-only: % is forbidden. sequence_number=%',
                    TG_OP, OLD.sequence_number;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ral_deny_update BEFORE UPDATE ON relay_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_relay_audit_modification();"
        )
    )
    conn.execute(
        sa.text(
            "CREATE TRIGGER trg_ral_deny_delete BEFORE DELETE ON relay_audit_log "
            "FOR EACH ROW EXECUTE FUNCTION deny_relay_audit_modification();"
        )
    )

    # ------------------------------------------------------------------ #
    # 3. No RLS, no orchestrator_app grants — accessed ONLY via the privileged session
    #    (mirrors the sentinel_registry_audit_log / distribution_audit_log precedent).
    # ------------------------------------------------------------------ #


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ral_deny_update ON relay_audit_log"))
    conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_ral_deny_delete ON relay_audit_log"))
    conn.execute(sa.text("DROP FUNCTION IF EXISTS deny_relay_audit_modification()"))

    op.drop_table("relay_audit_log")
