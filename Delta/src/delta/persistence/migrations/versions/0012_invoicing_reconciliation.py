"""Delta automated invoicing + vendor payment reconciliation (D-018).

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-09

The roadmap's literal text for D-018 is: "Invoicing + vendor payment reconciliation
linked to project milestones/delivery metrics; continuous ERP ledger reconciliation."
This migration scopes that down to a deliberately bounded vertical slice (ADR-0018):
a classic accounts-payable three-way match — D-014 purchase order (commitment) ->
invoice (vendor's billing claim, optionally proven by a D-015 task's 'done' status as
the delivery-metric leg) -> recorded payments (settlement) — plus a computed
reconciliation report that flags any drift between committed/invoiced/paid totals per
vendor. It does NOT wire vendor payments into D-003's ledger_entries/transactions
tables: that ledger's rows are structurally attributed to Sentinel's four AI-usage
stable IDs (team/project/agent), not vendor accounts-payable, and D-014 itself never
touched the ledger for the identical reason (verified: no `ledger`/`Transaction`
reference anywhere in `delta.erp`). Real continuous reconciliation against an actual
bank feed or corporate ERP system is D-019's explicit job per the roadmap ("Corporate
ERP integrations... for continuous ledger reconciliation... Depends on: D-014, D-018").
See docs/adr/0018-delta-invoicing-reconciliation.md §3 for the full honesty boundary.

Two new tables:

1. ``invoices`` — one row per vendor invoice submitted against an approved D-014
   purchase order. ``amount_paid_minor_units`` is a denormalized running total (never
   negative, never exceeding ``amount_minor_units`` — both enforced by CHECK
   constraints as a second, independent layer beneath the service-level guard).
   ``status`` moves forward only: submitted -> approved|disputed -> (approved)
   partially_paid -> paid (enforced by ``delta.invoicing.store``'s conditional
   UPDATEs, mirroring D-007/D-013/D-014's own conditional-decision shape — not a DB
   CHECK, since the linear vocabulary could still grow).
2. ``invoice_payments`` — an append-only ledger of recorded vendor payments against
   an invoice (no UPDATE/DELETE grant — the invoice's own running total is the one
   mutable projection).

Composite tenant-scoped FKs: ``invoices.(vendor_id, tenant_id)`` -> ``vendors``,
``invoices.(po_id, tenant_id)`` -> ``purchase_orders``,
``invoice_payments.(invoice_id, tenant_id)`` -> ``invoices`` — mirrors migration
0010's ``tasks.(team_id, tenant_id)`` -> ``teams`` precedent (structurally prevents
cross-tenant reference regardless of RLS). ``milestone_task_id`` is left as a plain
column (no FK): ``tasks`` has no ``UniqueConstraint(task_id, tenant_id)`` to reference
(migration 0009 never added one — only ``task_id`` is the primary key), so
``delta.invoicing.service`` validates task existence/tenant/status at the application
layer instead, the same choice migration 0010 made for zero comparable precedent
tables.

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE on ``invoices`` (payment recording
and decisions are UPDATEs) and SELECT, INSERT (no UPDATE, no DELETE) on
``invoice_payments`` — an append-only settlement ledger. Same strict fail-closed
NULLIF RLS predicate as every prior migration.

DOWN: drops both tables (payments first, FK dependency order). Retains the ``delta``
schema and never touches D-001..D-017 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str, *, insert: bool, update: bool) -> None:
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
    # ----------------------------------------------------------------------- invoices
    op.create_table(
        "invoices",
        sa.Column("invoice_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("vendor_id", sa.String(64), nullable=False),
        sa.Column("po_id", sa.String(64), nullable=False),
        sa.Column("milestone_task_id", sa.String(64), nullable=True),
        sa.Column("invoice_number", sa.String(128), nullable=False),
        sa.Column("description", sa.String(512), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("amount_paid_minor_units", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("submitted_by", sa.String(128), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount_minor_units >= 0", name="ck_invoice_amount_nonneg"),
        sa.CheckConstraint("amount_paid_minor_units >= 0", name="ck_invoice_paid_nonneg"),
        sa.CheckConstraint(
            "amount_paid_minor_units <= amount_minor_units", name="ck_invoice_paid_le_amount"
        ),
        sa.CheckConstraint(
            "status IN ('submitted', 'approved', 'disputed', 'partially_paid', 'paid')",
            name="ck_invoice_status",
        ),
        sa.UniqueConstraint("invoice_id", "tenant_id", name="uq_invoice_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_invoice_vendor",
        "invoices",
        "vendors",
        ["vendor_id", "tenant_id"],
        ["vendor_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_invoice_po",
        "invoices",
        "purchase_orders",
        ["po_id", "tenant_id"],
        ["po_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index("ix_invoices_tenant", "invoices", ["tenant_id"], schema=_SCHEMA)
    op.create_index(
        "ix_invoices_tenant_vendor", "invoices", ["tenant_id", "vendor_id"], schema=_SCHEMA
    )
    op.create_index("ix_invoices_tenant_po", "invoices", ["tenant_id", "po_id"], schema=_SCHEMA)
    op.create_index(
        "ix_invoices_tenant_status", "invoices", ["tenant_id", "status"], schema=_SCHEMA
    )

    # -------------------------------------------------------------- invoice_payments
    op.create_table(
        "invoice_payments",
        sa.Column("payment_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("invoice_id", sa.String(64), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_by", sa.String(128), nullable=False),
        sa.Column("note", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount_minor_units > 0", name="ck_invoice_payment_amount_positive"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_invoice_payment_invoice",
        "invoice_payments",
        "invoices",
        ["invoice_id", "tenant_id"],
        ["invoice_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index("ix_invoice_payments_tenant", "invoice_payments", ["tenant_id"], schema=_SCHEMA)
    op.create_index(
        "ix_invoice_payments_tenant_invoice",
        "invoice_payments",
        ["tenant_id", "invoice_id"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.invoices TO {_APP_ROLE}")
    _enable_rls("invoices", insert=True, update=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.invoice_payments TO {_APP_ROLE}")
    _enable_rls("invoice_payments", insert=True, update=False)


def downgrade() -> None:
    op.execute(
        f"DROP POLICY IF EXISTS invoice_payments_tenant_insert ON {_SCHEMA}.invoice_payments"
    )
    op.execute(
        f"DROP POLICY IF EXISTS invoice_payments_tenant_select ON {_SCHEMA}.invoice_payments"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.invoice_payments FROM {_APP_ROLE}")

    op.drop_index(
        "ix_invoice_payments_tenant_invoice", table_name="invoice_payments", schema=_SCHEMA
    )
    op.drop_index("ix_invoice_payments_tenant", table_name="invoice_payments", schema=_SCHEMA)
    op.drop_constraint(
        "fk_invoice_payment_invoice", "invoice_payments", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("invoice_payments", schema=_SCHEMA)

    op.execute(f"DROP POLICY IF EXISTS invoices_tenant_update ON {_SCHEMA}.invoices")
    op.execute(f"DROP POLICY IF EXISTS invoices_tenant_insert ON {_SCHEMA}.invoices")
    op.execute(f"DROP POLICY IF EXISTS invoices_tenant_select ON {_SCHEMA}.invoices")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.invoices FROM {_APP_ROLE}")

    op.drop_index("ix_invoices_tenant_status", table_name="invoices", schema=_SCHEMA)
    op.drop_index("ix_invoices_tenant_po", table_name="invoices", schema=_SCHEMA)
    op.drop_index("ix_invoices_tenant_vendor", table_name="invoices", schema=_SCHEMA)
    op.drop_index("ix_invoices_tenant", table_name="invoices", schema=_SCHEMA)
    op.drop_constraint("fk_invoice_po", "invoices", schema=_SCHEMA, type_="foreignkey")
    op.drop_constraint("fk_invoice_vendor", "invoices", schema=_SCHEMA, type_="foreignkey")
    op.drop_table("invoices", schema=_SCHEMA)
