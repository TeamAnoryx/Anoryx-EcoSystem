"""Per-tenant query principal + read-seam cursor indexes (O-006, ADR-0006).

Revision ID: 0005_tenant_principal_and_reads
Revises: 0004_sentinel_registry
Create Date: 2026-07-02

Extends the live head (0004_sentinel_registry) with the O-006 persistence consolidation.
Deliberately LIGHT + ADDITIVE (Fork A1): the tables are already coherent + RLS'd, so this
migration only:

  1. CREATEs query_service_tokens — the OPERATOR-GLOBAL per-tenant read/query principal
     (like sentinel_registry: NO RLS, NO orchestrator_app grants — the auth lookup must
     resolve the tenant BEFORE a tenant GUC can be set, so it is privileged-read only). A
     UNIQUE index on token_sha256 backs the auth lookup.
  2. CREATEs two cursor indexes supporting the bounded metadata read seams:
       ix_ingest_events_tenant_seq         on ingest_events (tenant_id, sequence_number)
       ix_dead_letter_queue_tenant_created on dead_letter_queue (tenant_id, created_at, dlq_id)

NO RLS statements (the new table is operator-global; the existing tenant tables already have
correct RLS). NO changes to any audit-chain table or column — the three hash chains stay
verifiable across this migration by construction (Fork A1). Reversible: downgrade drops the
indexes + table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_tenant_principal_and_reads"
down_revision: Union[str, None] = "0004_sentinel_registry"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # 1. query_service_tokens — operator-global per-tenant principal (no RLS, no grants).
    # ------------------------------------------------------------------ #
    op.create_table(
        "query_service_tokens",
        sa.Column("token_id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        # SHA-256 hex of the presented Bearer secret (plaintext is never stored). UNIQUE via
        # the named index below (the auth lookup key).
        sa.Column("token_sha256", sa.String(64), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_qst_token_sha256", "query_service_tokens", ["token_sha256"], unique=True)

    # No RLS, no orchestrator_app grants. query_service_tokens is the auth-bootstrap table:
    # it is resolved on the PRIVILEGED (owner) session BEFORE any tenant GUC is set, so it
    # cannot be RLS-scoped on itself, and the app role has no reason to read it (least
    # privilege, mirrors the sentinel_registry precedent in 0004).

    # ------------------------------------------------------------------ #
    # 2. Cursor indexes for the bounded, tenant-scoped metadata read seams.
    # ------------------------------------------------------------------ #
    # GET /v1/events — cursor scans on sequence_number within a tenant.
    op.create_index(
        "ix_ingest_events_tenant_seq", "ingest_events", ["tenant_id", "sequence_number"]
    )
    # GET /v1/bus/dlq — cursor scans on (created_at, dlq_id) within a tenant.
    op.create_index(
        "ix_dead_letter_queue_tenant_created",
        "dead_letter_queue",
        ["tenant_id", "created_at", "dlq_id"],
    )


def downgrade() -> None:
    # Drop the read indexes, then the principal table's index + table (FK-safe: no FKs).
    op.drop_index("ix_dead_letter_queue_tenant_created", table_name="dead_letter_queue")
    op.drop_index("ix_ingest_events_tenant_seq", table_name="ingest_events")
    op.drop_index("ix_qst_token_sha256", table_name="query_service_tokens")
    op.drop_table("query_service_tokens")
