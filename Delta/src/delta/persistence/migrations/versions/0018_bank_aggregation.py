"""Delta privacy-first multi-bank financial data aggregation (D-025, ADR-0025).

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-11

D-021's own ADR-0021 named this task's job precisely: "No real bank data
aggregation... D-025's named job — a generic ingestion framework (mirroring D-019's
own precedent), not live Plaid/bank OAuth" (ADR-0021 Sec 3). This migration is that
job's persistence half: a consent-scoped, generic ingestion framework, NOT a live
bank/OAuth connector (no such credential or integration exists anywhere in this
codebase or environment).

Three new tables:

1. ``linked_institutions`` -- a consent record linking exactly one D-021
   `personal_accounts` row to a named institution. Privacy-first, enforced at the
   DB layer: `masked_account_last4` is CHECK-constrained to exactly four digits — it
   is structurally impossible to store a full account/routing number here, not just
   an app-layer convention. A partial UNIQUE index allows at most one 'linked' row
   per account at a time (an account may be unlinked and later re-linked, each a
   new row, but never two simultaneously active links). `delta_app` gets UPDATE
   (forward-only 'linked' -> 'revoked', mirrors D-014/D-022's conditional-transition
   pattern) in addition to SELECT/INSERT.
2. ``aggregation_sync_runs`` -- one append-only row per sync call, summarizing how
   many line items were received/written/deduplicated/rejected (mirrors D-019's
   `sync_runs`). No UPDATE/DELETE grant — every run is a fact about what happened,
   never revised.
3. ``aggregation_ingested_references`` -- the idempotent-ingestion backstop: a
   composite PRIMARY KEY of `(link_id, external_reference)` makes re-ingesting the
   same bank-reported transaction (e.g. a retried sync call) structurally
   impossible, mirroring D-024's `UNIQUE(tenant_id, idempotency_key)`. No
   UPDATE/DELETE grant.

Also widens D-021's `ck_personal_txn_source` CHECK (already widened once, by D-024,
from `('manual')` to `('manual', 'execution')`) to add `'aggregated'` — an ingested
bank transaction lands in the SAME `personal_transactions` ledger every D-021 read
(budgets, health score, category spend) already consumes, exactly as D-024 exercised
this same designed extension point for its own `'execution'` source.

DOWN: drops all three new tables and restores the narrower source CHECK. NOTE: the
downgrade's narrower CHECK re-add fails by design if any `source='aggregated'` rows
exist — deleting a tenant's real ledger rows in a schema downgrade would be worse
than failing loudly (CI's migration-roundtrip job runs on an empty database, where
this reverses cleanly).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str, *, insert: bool, update: bool = False) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {table}_tenant_select ON {_SCHEMA}.{table} "
        f"FOR SELECT USING ({_TENANT_PREDICATE})"
    )
    if insert:
        op.execute(
            f"CREATE POLICY {table}_tenant_insert ON {_SCHEMA}.{table} "
            f"FOR INSERT WITH CHECK ({_TENANT_PREDICATE})"
        )
    if update:
        op.execute(
            f"CREATE POLICY {table}_tenant_update ON {_SCHEMA}.{table} "
            f"FOR UPDATE USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
        )


def upgrade() -> None:
    # ---------------------------------------------------------------- linked_institutions
    op.create_table(
        "linked_institutions",
        sa.Column("link_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("institution_name", sa.String(256), nullable=False),
        sa.Column("masked_account_last4", sa.String(4), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("consent_granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consent_revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "masked_account_last4 ~ '^[0-9]{4}$'", name="ck_linked_institution_masked_last4"
        ),
        sa.CheckConstraint("status IN ('linked', 'revoked')", name="ck_linked_institution_status"),
        sa.CheckConstraint(
            "(status = 'revoked') = (consent_revoked_at IS NOT NULL)",
            name="ck_linked_institution_revoked_consistency",
        ),
        sa.UniqueConstraint("link_id", "tenant_id", name="uq_linked_institution_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_linked_institution_account",
        "linked_institutions",
        "personal_accounts",
        ["account_id", "tenant_id"],
        ["account_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    # At most one ACTIVE link per account (partial unique index, not a plain
    # UniqueConstraint) -- an account may be unlinked and later re-linked, each a
    # new row, but never two simultaneously 'linked' rows for one account.
    op.execute(
        f"CREATE UNIQUE INDEX uq_linked_institution_active_account "
        f"ON {_SCHEMA}.linked_institutions (account_id) WHERE status = 'linked'"
    )
    op.create_index(
        "ix_linked_institutions_tenant", "linked_institutions", ["tenant_id"], schema=_SCHEMA
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.linked_institutions TO {_APP_ROLE}")
    _enable_rls("linked_institutions", insert=True, update=True)

    # ------------------------------------------------------------- aggregation_sync_runs
    op.create_table(
        "aggregation_sync_runs",
        sa.Column("sync_run_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("link_id", sa.String(64), nullable=False),
        sa.Column("triggered_by", sa.String(128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("records_received", sa.Integer, nullable=False),
        sa.Column("records_written", sa.Integer, nullable=False),
        sa.Column("records_deduplicated", sa.Integer, nullable=False),
        sa.Column("records_rejected", sa.Integer, nullable=False),
        sa.Column("note", sa.String(1024), nullable=True),
        sa.CheckConstraint(
            "records_received = records_written + records_deduplicated + records_rejected",
            name="ck_aggregation_sync_run_counts_consistent",
        ),
        sa.CheckConstraint("records_received >= 0", name="ck_aggregation_sync_run_received_nonneg"),
        sa.CheckConstraint("records_written >= 0", name="ck_aggregation_sync_run_written_nonneg"),
        sa.CheckConstraint(
            "records_deduplicated >= 0", name="ck_aggregation_sync_run_deduplicated_nonneg"
        ),
        sa.CheckConstraint("records_rejected >= 0", name="ck_aggregation_sync_run_rejected_nonneg"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_aggregation_sync_run_link",
        "aggregation_sync_runs",
        "linked_institutions",
        ["link_id", "tenant_id"],
        ["link_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_aggregation_sync_runs_link", "aggregation_sync_runs", ["link_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_aggregation_sync_runs_tenant", "aggregation_sync_runs", ["tenant_id"], schema=_SCHEMA
    )
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.aggregation_sync_runs TO {_APP_ROLE}")
    _enable_rls("aggregation_sync_runs", insert=True)

    # ------------------------------------------------- aggregation_ingested_references
    op.create_table(
        "aggregation_ingested_references",
        sa.Column("link_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("external_reference", sa.String(128), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("txn_id", sa.String(64), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_aggregation_ingested_ref_link",
        "aggregation_ingested_references",
        "linked_institutions",
        ["link_id", "tenant_id"],
        ["link_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_aggregation_ingested_ref_txn",
        "aggregation_ingested_references",
        "personal_transactions",
        ["txn_id"],
        ["txn_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_aggregation_ingested_references_tenant",
        "aggregation_ingested_references",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.aggregation_ingested_references TO {_APP_ROLE}")
    _enable_rls("aggregation_ingested_references", insert=True)

    # ------------------------------------------ widen personal_transactions source CHECK
    op.drop_constraint("ck_personal_txn_source", "personal_transactions", schema=_SCHEMA)
    op.create_check_constraint(
        "ck_personal_txn_source",
        "personal_transactions",
        "source IN ('manual', 'execution', 'aggregated')",
        schema=_SCHEMA,
    )


def downgrade() -> None:
    # Restore the D-024-era two-value source CHECK (fails loudly if 'aggregated'
    # rows exist -- see the module docstring; never deletes ledger rows).
    op.drop_constraint("ck_personal_txn_source", "personal_transactions", schema=_SCHEMA)
    op.create_check_constraint(
        "ck_personal_txn_source",
        "personal_transactions",
        "source IN ('manual', 'execution')",
        schema=_SCHEMA,
    )

    op.execute(
        "DROP POLICY IF EXISTS aggregation_ingested_references_tenant_insert "
        f"ON {_SCHEMA}.aggregation_ingested_references"
    )
    op.execute(
        "DROP POLICY IF EXISTS aggregation_ingested_references_tenant_select "
        f"ON {_SCHEMA}.aggregation_ingested_references"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.aggregation_ingested_references FROM {_APP_ROLE}")
    op.drop_index(
        "ix_aggregation_ingested_references_tenant",
        table_name="aggregation_ingested_references",
        schema=_SCHEMA,
    )
    op.drop_constraint(
        "fk_aggregation_ingested_ref_txn",
        "aggregation_ingested_references",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_aggregation_ingested_ref_link",
        "aggregation_ingested_references",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_table("aggregation_ingested_references", schema=_SCHEMA)

    op.execute(
        "DROP POLICY IF EXISTS aggregation_sync_runs_tenant_insert "
        f"ON {_SCHEMA}.aggregation_sync_runs"
    )
    op.execute(
        "DROP POLICY IF EXISTS aggregation_sync_runs_tenant_select "
        f"ON {_SCHEMA}.aggregation_sync_runs"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.aggregation_sync_runs FROM {_APP_ROLE}")
    op.drop_index(
        "ix_aggregation_sync_runs_tenant", table_name="aggregation_sync_runs", schema=_SCHEMA
    )
    op.drop_index(
        "ix_aggregation_sync_runs_link", table_name="aggregation_sync_runs", schema=_SCHEMA
    )
    op.drop_constraint(
        "fk_aggregation_sync_run_link",
        "aggregation_sync_runs",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_table("aggregation_sync_runs", schema=_SCHEMA)

    op.execute(
        f"DROP POLICY IF EXISTS linked_institutions_tenant_update ON {_SCHEMA}.linked_institutions"
    )
    op.execute(
        f"DROP POLICY IF EXISTS linked_institutions_tenant_insert ON {_SCHEMA}.linked_institutions"
    )
    op.execute(
        f"DROP POLICY IF EXISTS linked_institutions_tenant_select ON {_SCHEMA}.linked_institutions"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.linked_institutions FROM {_APP_ROLE}")
    op.execute(f"DROP INDEX IF EXISTS {_SCHEMA}.uq_linked_institution_active_account")
    op.drop_index("ix_linked_institutions_tenant", table_name="linked_institutions", schema=_SCHEMA)
    op.drop_constraint(
        "fk_linked_institution_account", "linked_institutions", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("linked_institutions", schema=_SCHEMA)
