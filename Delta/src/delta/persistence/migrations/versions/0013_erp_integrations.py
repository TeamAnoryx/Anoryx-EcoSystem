"""Delta corporate ERP/procurement/cloud-cost sync connectors (D-019).

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-10

The roadmap's literal text for D-019 is: "Seamless integration with corporate ERPs
for continuous ledger reconciliation; cloud cost sync; procurement," naming SEVEN
specific third-party systems (NetSuite, SAP, Coupa, Ariba, AWS, GCP, Azure) at
"28h+ each." This migration scopes that down to a deliberately bounded vertical slice
(ADR-0019): a generic external-system registration + sync-ingestion + reconciliation-
matching FRAMEWORK, reusing D-014's purchase orders and D-018's invoices as the
Delta-side reconciliation target — not seven live OAuth/API integrations with real
third-party credentials, which this unattended task cannot responsibly build or test
(no real NetSuite/SAP/Coupa/Ariba/AWS/GCP/Azure account exists in this environment).
The natural integration point for a future per-vendor connector is named explicitly:
normalize that vendor's data into this migration's `sync_line_items` shape and POST
it through the same ingestion endpoint this task builds. See
docs/adr/0019-delta-erp-integrations.md §3 for the full honesty boundary.

Three new tables:

1. ``external_systems`` — a registered connector target (operator-declared
   `vendor_label` like "NetSuite"/"AWS" — a free-text label, not a live integration).
2. ``sync_runs`` — one row per sync ingestion. Fully synchronous (the line items are
   supplied directly by the caller in this task — no live external I/O), so there is
   no run-level failure/retry state; the five ``records_*`` columns are a
   denormalized summary written once, never updated.
3. ``sync_line_items`` — the ingested rows themselves, each independently matched
   against a D-014 purchase order or D-018 invoice by ``po_id``/``invoice_id`` +
   exact amount/currency comparison (a precise ID-based match, not fuzzy
   string/amount heuristics — ADR-0019 Fork 2).

Composite tenant-scoped FKs: ``sync_runs.(system_id, tenant_id)`` ->
``external_systems``, ``sync_line_items.(sync_run_id, tenant_id)`` -> ``sync_runs`` —
mirrors migration 0012's identical precedent. ``sync_line_items`` does NOT carry a FK
to ``purchase_orders``/``invoices``: a 'not_found' match is an expected, valid
outcome (the caller-supplied reference didn't resolve), not a referential-integrity
violation, so the reference is validated at the application layer (mirrors D-018
migration 0012's identical choice for ``milestone_task_id``).

Grants: ``delta_app`` gets SELECT, INSERT only on all three tables — no UPDATE, no
DELETE anywhere in this feature (every row is written once and never revised, a
simpler write pattern than every prior Delta migration since there is no shared
running total to guard against concurrent mutation). Same strict fail-closed NULLIF
RLS predicate as every prior migration.

DOWN: drops all three tables (line items, then runs, then systems — FK dependency
order). Retains the ``delta`` schema and never touches D-001..D-018 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str, *, insert: bool) -> None:
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


def upgrade() -> None:
    # --------------------------------------------------------------- external_systems
    op.create_table(
        "external_systems",
        sa.Column("system_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("system_type", sa.String(16), nullable=False),
        sa.Column("vendor_label", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "system_type IN ('corporate_erp', 'procurement', 'cloud_cost')",
            name="ck_external_system_type",
        ),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_external_system_status"),
        sa.UniqueConstraint("system_id", "tenant_id", name="uq_external_system_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_external_systems_tenant", "external_systems", ["tenant_id"], schema=_SCHEMA)

    # ------------------------------------------------------------------------ sync_runs
    op.create_table(
        "sync_runs",
        sa.Column("sync_run_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("system_id", sa.String(64), nullable=False),
        sa.Column("triggered_by", sa.String(128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("records_ingested", sa.Integer, nullable=False),
        sa.Column("records_matched", sa.Integer, nullable=False),
        sa.Column("records_mismatched", sa.Integer, nullable=False),
        sa.Column("records_not_found", sa.Integer, nullable=False),
        sa.Column("records_unreconciled", sa.Integer, nullable=False),
        sa.Column("note", sa.String(1024), nullable=True),
        sa.CheckConstraint("records_ingested >= 0", name="ck_sync_run_ingested_nonneg"),
        sa.CheckConstraint(
            "records_ingested = records_matched + records_mismatched + records_not_found "
            "+ records_unreconciled",
            name="ck_sync_run_counts_sum",
        ),
        sa.UniqueConstraint("sync_run_id", "tenant_id", name="uq_sync_run_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_sync_run_system",
        "sync_runs",
        "external_systems",
        ["system_id", "tenant_id"],
        ["system_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index("ix_sync_runs_tenant", "sync_runs", ["tenant_id"], schema=_SCHEMA)
    op.create_index(
        "ix_sync_runs_tenant_system", "sync_runs", ["tenant_id", "system_id"], schema=_SCHEMA
    )

    # ------------------------------------------------------------------ sync_line_items
    op.create_table(
        "sync_line_items",
        sa.Column("line_item_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("sync_run_id", sa.String(64), nullable=False),
        sa.Column("external_reference", sa.String(256), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("matched_status", sa.String(16), nullable=False),
        sa.Column("matched_entity_type", sa.String(16), nullable=True),
        sa.Column("matched_entity_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount_minor_units >= 0", name="ck_sync_line_item_amount_nonneg"),
        sa.CheckConstraint(
            "matched_status IN ('matched', 'amount_mismatch', 'not_found', 'unreconciled')",
            name="ck_sync_line_item_status",
        ),
        sa.CheckConstraint(
            "matched_entity_type IS NULL OR matched_entity_type IN "
            "('purchase_order', 'invoice')",
            name="ck_sync_line_item_entity_type",
        ),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_sync_line_item_run",
        "sync_line_items",
        "sync_runs",
        ["sync_run_id", "tenant_id"],
        ["sync_run_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index("ix_sync_line_items_tenant", "sync_line_items", ["tenant_id"], schema=_SCHEMA)
    op.create_index(
        "ix_sync_line_items_tenant_run",
        "sync_line_items",
        ["tenant_id", "sync_run_id"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.external_systems TO {_APP_ROLE}")
    _enable_rls("external_systems", insert=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.sync_runs TO {_APP_ROLE}")
    _enable_rls("sync_runs", insert=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.sync_line_items TO {_APP_ROLE}")
    _enable_rls("sync_line_items", insert=True)


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS sync_line_items_tenant_insert ON {_SCHEMA}.sync_line_items")
    op.execute(f"DROP POLICY IF EXISTS sync_line_items_tenant_select ON {_SCHEMA}.sync_line_items")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.sync_line_items FROM {_APP_ROLE}")

    op.drop_index("ix_sync_line_items_tenant_run", table_name="sync_line_items", schema=_SCHEMA)
    op.drop_index("ix_sync_line_items_tenant", table_name="sync_line_items", schema=_SCHEMA)
    op.drop_constraint(
        "fk_sync_line_item_run", "sync_line_items", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("sync_line_items", schema=_SCHEMA)

    op.execute(f"DROP POLICY IF EXISTS sync_runs_tenant_insert ON {_SCHEMA}.sync_runs")
    op.execute(f"DROP POLICY IF EXISTS sync_runs_tenant_select ON {_SCHEMA}.sync_runs")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.sync_runs FROM {_APP_ROLE}")

    op.drop_index("ix_sync_runs_tenant_system", table_name="sync_runs", schema=_SCHEMA)
    op.drop_index("ix_sync_runs_tenant", table_name="sync_runs", schema=_SCHEMA)
    op.drop_constraint("fk_sync_run_system", "sync_runs", schema=_SCHEMA, type_="foreignkey")
    op.drop_table("sync_runs", schema=_SCHEMA)

    op.execute(
        f"DROP POLICY IF EXISTS external_systems_tenant_insert ON {_SCHEMA}.external_systems"
    )
    op.execute(
        f"DROP POLICY IF EXISTS external_systems_tenant_select ON {_SCHEMA}.external_systems"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.external_systems FROM {_APP_ROLE}")

    op.drop_index("ix_external_systems_tenant", table_name="external_systems", schema=_SCHEMA)
    op.drop_table("external_systems", schema=_SCHEMA)
