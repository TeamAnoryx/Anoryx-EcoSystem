"""Delta event-ingest posting layer (D-004): same-tenant account FK + ingest DLQ.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-30

This migration is the posting-layer half of D-004. It closes D-003's deferred
HIGH#2 and adds the dead-letter sink the ingest pipeline writes unmappable events
to. It introduces NO float and NO new money path; amounts stay BIGINT integer cents
in the D-003 tables.

1. Same-tenant account FK (ADR-0004 Fork 1a, closes D-003 HIGH#2). D-003 shipped
   ``ledger_entries.account_id`` with NO FK to ``accounts`` — the event->account
   mapping and chart-of-accounts lifecycle were deferred to "the posting layer
   (D-004 ingest)". We add it now, before any posting volume:
     - a composite UNIQUE (tenant_id, account_id) on delta.accounts (the FK target;
       account_id is already PK, so this is an added composite key, not a relaxation),
     - a composite FK ledger_entries(tenant_id, account_id) -> accounts(tenant_id,
       account_id). An entry can now only reference an account that EXISTS and shares
       the entry's tenant_id. Combined with RLS this makes a cross-tenant or dangling
       account reference impossible at the database (threat vectors 1, 7).
   CONSEQUENCE: every ledger_entries insert now requires its (tenant, account) to
   exist in accounts first. D-004's resolver get-or-creates the two canonical
   accounts per tenant before posting; D-003's own tests seed accounts before
   appending (the documented Fork 1a cost).

2. delta.ingest_dead_letter (ADR-0004 Fork 5). A financial event that cannot be
   posted (unknown tenant, invalid/negative cost, unresolvable account, malformed
   payload) is dead-lettered, never silently dropped. Mirrors the Orchestrator
   dead_letter_queue: full original_payload (JSONB) preserved, a closed reason set,
   bounded attempt_count, first/last_failed_at. RLS tenant-scoped (tenant rows are
   tenant-visible); unknown-tenant rows carry tenant_id NULL and are written via the
   privileged session (RLS-invisible to delta_app), exactly as the Orchestrator does.
   INSERT-only at the grant layer (SELECT+INSERT, no UPDATE/DELETE). A partial UNIQUE
   (tenant_id, source_event_id) bounds duplicate dead-letters from a redelivered
   poison event (threat vector 8).

DOWN: drops the DLQ (policies, grants, indexes, table) then the FK then the unique
key, in dependency order. Reversible round-trip on a fresh DB. Never touches tenant
data and never drops the ``delta`` schema (it houses alembic_version).
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

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

# Identical fail-closed RLS predicate to 0001 (F-003b Option α shape).
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# The closed set of dead-letter reasons. Holds only events Delta received and could not
# post; dispatcher retry-exhaustion is audited by the Orchestrator forward_outbox 'failed'
# row, NOT a Delta DLQ row — so there is no "max_attempts_exceeded" reason here.
_DLQ_REASONS = (
    "unknown_tenant",
    "invalid_cost",
    "unresolvable_account",
    "malformed_payload",
)


def _enable_dlq_rls() -> None:
    """ENABLE + FORCE RLS on ingest_dead_letter: tenant-scoped SELECT/INSERT,
    UPDATE/DELETE unsatisfiable (insert-only). Same shape as 0001's ledger policies.
    """
    op.execute(f"ALTER TABLE {_SCHEMA}.ingest_dead_letter ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.ingest_dead_letter FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY ingest_dead_letter_tenant_select ON {_SCHEMA}.ingest_dead_letter "
        f"FOR SELECT USING ({_TENANT_PREDICATE})"
    )
    op.execute(
        f"CREATE POLICY ingest_dead_letter_tenant_insert ON {_SCHEMA}.ingest_dead_letter "
        f"FOR INSERT WITH CHECK ({_TENANT_PREDICATE})"
    )
    op.execute(
        f"CREATE POLICY ingest_dead_letter_deny_update ON {_SCHEMA}.ingest_dead_letter "
        f"FOR UPDATE USING (false)"
    )
    op.execute(
        f"CREATE POLICY ingest_dead_letter_deny_delete ON {_SCHEMA}.ingest_dead_letter "
        f"FOR DELETE USING (false)"
    )


def upgrade() -> None:
    # ---------------------------------------------- 1. same-tenant account FK
    # The composite UNIQUE is the FK target. account_id is already PK (globally
    # unique), so (tenant_id, account_id) is a guaranteed-unique superset key.
    op.create_unique_constraint(
        "uq_accounts_tenant_account",
        "accounts",
        ["tenant_id", "account_id"],
        schema=_SCHEMA,
    )
    # An entry's (tenant_id, account_id) must reference a real, same-tenant account.
    op.create_foreign_key(
        "fk_entry_account",
        source_table="ledger_entries",
        referent_table="accounts",
        local_cols=["tenant_id", "account_id"],
        remote_cols=["tenant_id", "account_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )

    # ------------------------------------------------ 2. ingest_dead_letter
    reason_check = "reason IN (" + ", ".join(f"'{r}'" for r in _DLQ_REASONS) + ")"
    op.create_table(
        "ingest_dead_letter",
        sa.Column("dlq_id", sa.String(64), primary_key=True, nullable=False),
        # NULL when the event's tenant is unknown/unresolvable -> written via the
        # privileged session and invisible to the tenant-scoped delta_app role.
        sa.Column("tenant_id", sa.String(64), nullable=True),
        # The Sentinel event_id (idempotency / correlation), when extractable.
        sa.Column("source_event_id", sa.String(64), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=True),
        sa.Column("reason", sa.String(32), nullable=False),
        # Full original event preserved verbatim (auditable, never lost).
        sa.Column("original_payload", postgresql.JSONB, nullable=False),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("first_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(reason_check, name="ck_dlq_reason"),
        sa.CheckConstraint("attempt_count >= 0", name="ck_dlq_attempt_nonneg"),
        schema=_SCHEMA,
    )
    op.create_index("ix_dlq_tenant", "ingest_dead_letter", ["tenant_id"], schema=_SCHEMA)
    # Bound duplicate dead-letters from a redelivered poison event (vector 8):
    # at most one DLQ row per (tenant, source_event_id) when both are present.
    op.create_index(
        "ux_dlq_tenant_event",
        "ingest_dead_letter",
        ["tenant_id", "source_event_id"],
        schema=_SCHEMA,
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL AND source_event_id IS NOT NULL"),
    )
    # Append-only at the grant layer: SELECT + INSERT only, never UPDATE/DELETE.
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.ingest_dead_letter TO {_APP_ROLE}")
    _enable_dlq_rls()


def downgrade() -> None:
    # Reverse dependency order. Never drops the `delta` schema or tenant data.
    op.execute(
        f"DROP POLICY IF EXISTS ingest_dead_letter_deny_delete ON {_SCHEMA}.ingest_dead_letter"
    )
    op.execute(
        f"DROP POLICY IF EXISTS ingest_dead_letter_deny_update ON {_SCHEMA}.ingest_dead_letter"
    )
    op.execute(
        f"DROP POLICY IF EXISTS ingest_dead_letter_tenant_insert ON {_SCHEMA}.ingest_dead_letter"
    )
    op.execute(
        f"DROP POLICY IF EXISTS ingest_dead_letter_tenant_select ON {_SCHEMA}.ingest_dead_letter"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.ingest_dead_letter FROM {_APP_ROLE}")
    op.drop_index("ux_dlq_tenant_event", table_name="ingest_dead_letter", schema=_SCHEMA)
    op.drop_index("ix_dlq_tenant", table_name="ingest_dead_letter", schema=_SCHEMA)
    op.drop_table("ingest_dead_letter", schema=_SCHEMA)

    op.drop_constraint("fk_entry_account", "ledger_entries", schema=_SCHEMA, type_="foreignkey")
    op.drop_constraint("uq_accounts_tenant_account", "accounts", schema=_SCHEMA, type_="unique")
