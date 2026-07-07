"""Rendly R-008 Sentinel safety: message detector findings + inspection audit log.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-07

The THIRD Rendly DDL. Closes two gaps R-005 left RESERVED for R-008 (ADR-0001 D4 / ADR-0008):

1. ``messages.detectors`` — a JSONB column carrying the per-category (pii/injection/secret)
   findings the seam evaluated for a persisted (always-``pass``) message, so the wire's
   previously-reserved ``InspectionResult.detectors`` can be rebuilt faithfully from a row.
   Metadata only ([{"category": ..., "outcome": ...}, ...]) — content is NEVER stored here.

2. ``inspection_audit_log`` (new RLS table) — the administrative-oversight complement to
   ``messages``: a BLOCKED or SEAM-UNAVAILABLE send is fail-closed and never persisted in
   ``messages`` (by design — R-001 D4), so without a separate record a rejected send leaves NO
   trace anywhere, not even for an admin. This table records exactly that: tenant_id,
   channel_id, sender_user_id, the terminal status, the per-detector findings (metadata only,
   NEVER the offending content), and the evaluation/record timestamps. Mirrors the 0002 RLS +
   append-only-grant pattern exactly (OWNED ``rendly`` schema, ``rendly_app`` NOBYPASSRLS, the
   strict NULLIF tenant predicate, SELECT+INSERT only — never UPDATE/DELETE).

   HONESTY BOUNDARY (verbatim, non-removable): this is a plain append-only log, NOT a
   hash-chained tamper-evident audit trail — that construction (linking over ``seq`` with
   ``prev_record_hash``/``content_hash``) is R-009's job and is NOT built here. A dedicated
   admin-facing READ endpoint/scope over this table is also NOT built here (see ADR-0008) —
   this migration ships the data layer only.

DOWN: drops ``inspection_audit_log`` (policy -> grants -> table) and the ``messages.detectors``
column. Never touches ``channels``/``memberships``/``users``/``tenants`` (0001/0002 own those).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "rendly"
_APP_ROLE = "rendly_app"

# The strict fail-closed RLS predicate — IDENTICAL to 0001/0002.
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")
    op.execute(
        f"CREATE POLICY {table}_tenant ON {_SCHEMA}.{table} "
        f"FOR ALL USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    # --------------------------------------------------------------- messages.detectors
    op.add_column(
        "messages",
        sa.Column("detectors", JSONB, nullable=False, server_default=sa.text("'[]'")),
        schema=_SCHEMA,
    )

    # --------------------------------------------------------------- inspection_audit_log
    op.create_table(
        "inspection_audit_log",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("audit_id", sa.String(64), nullable=False),
        sa.Column("channel_id", sa.String(64), nullable=False),
        sa.Column("sender_user_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("detectors", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "audit_id", name="pk_inspection_audit_log"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "channel_id"],
            [f"{_SCHEMA}.channels.tenant_id", f"{_SCHEMA}.channels.channel_id"],
            name="fk_inspection_audit_log_channel",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "sender_user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_inspection_audit_log_sender",
        ),
        sa.CheckConstraint(
            "status IN ('blocked','seam_unavailable')", name="ck_inspection_audit_log_status"
        ),
        schema=_SCHEMA,
    )
    # The oversight query pattern is "this tenant's incidents, newest first" — index it directly
    # rather than relying on the PK (which is keyed by audit_id, not creation order).
    op.create_index(
        "ix_inspection_audit_log_tenant_created",
        "inspection_audit_log",
        ["tenant_id", "created_at"],
        schema=_SCHEMA,
    )

    # inspection_audit_log: read + insert ONLY — APPEND-ONLY by grant, identical posture to
    # messages. No UPDATE/DELETE; this is a plain log, not the R-009 hash chain.
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.inspection_audit_log TO {_APP_ROLE}")
    _enable_rls("inspection_audit_log")


def downgrade() -> None:
    op.execute(
        f"DROP POLICY IF EXISTS inspection_audit_log_tenant ON {_SCHEMA}.inspection_audit_log"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.inspection_audit_log FROM {_APP_ROLE}")
    op.drop_index(
        "ix_inspection_audit_log_tenant_created", table_name="inspection_audit_log", schema=_SCHEMA
    )
    op.drop_table("inspection_audit_log", schema=_SCHEMA)
    op.drop_column("messages", "detectors", schema=_SCHEMA)
