"""Delta ERP: vendors, assets, purchase_orders (D-014).

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-09

The Phase-3 (post-investment vision) roadmap item's literal text is "real-time sync of
supply chain, payroll, HR, and physical assets — the full ERP." This migration scopes
that down to a deliberately bounded vertical slice (ADR-0014): an internal asset
register and a vendor/purchase-order procurement workflow. Payroll and HR are entirely
out of scope (sensitive PII/compliance domains with zero precedent anywhere in this
codebase); "real-time sync" with external corporate ERPs is D-019's job, not this
task's — D-014 builds the internal record-keeping those future integrations would
sync into.

Three tables:

1. ``vendors`` — a tenant's vendor directory. Bare identity + status.
2. ``assets`` — the physical/software asset register. ``status`` moves forward only
   (active -> retired -> disposed), enforced at the app layer (delta.erp.service),
   not a DB CHECK — mirrors D-013's deal-stage terminality decision (ADR-0013 Fork 2):
   the actual invariant (no reverse transition) is enforced by a conditional UPDATE,
   not a closed DB-level vocabulary.
3. ``purchase_orders`` — a procurement commitment against a vendor, optionally tied to
   the asset it purchases (composite FK, same cross-tenant-proof pattern as D-007's
   ``allocation_targets`` and D-013's CRM tables). ``status`` starts 'requested'; only
   an explicit admin decision moves it to 'approved'/'rejected' — the EXACT same
   propose/decide shape as D-007's ``allocations`` table (down to the
   ``ck_po_decision_consistency`` CHECK), including the same conditional-UPDATE
   double-decision race guard. Unlike D-013's CRM edits, a PO decision IS a financial
   event and is wired into D-009's hash-chained audit log by ``delta.erp.service``
   (not by this migration — the audit rows land in the existing ``change_history``
   table, no new table needed for that).

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE on all three tables (status/decision
transitions on assets and purchase_orders; vendor status toggles) — never DELETE. Same
strict fail-closed NULLIF RLS predicate as every prior migration.

DOWN: reverses every object in dependency order. Retains the ``delta`` schema and never
touches D-001..D-013 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
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
    # --------------------------------------------------------------------------- vendors
    op.create_table(
        "vendors",
        sa.Column("vendor_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("contact_email", sa.String(320), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('active','inactive')", name="ck_vendor_status"),
        sa.UniqueConstraint("vendor_id", "tenant_id", name="uq_vendor_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_vendors_tenant", "vendors", ["tenant_id"], schema=_SCHEMA)

    # ---------------------------------------------------------------------------- assets
    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("acquisition_cost_minor_units", sa.BigInteger, nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_team_id", sa.String(64), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "acquisition_cost_minor_units IS NULL OR acquisition_cost_minor_units >= 0",
            name="ck_asset_cost_nonneg",
        ),
        # Same value/currency pairing discipline as D-013's deals table
        # (ADR-0013 §4 finding #1) — enforced here from the start, not post-audit.
        sa.CheckConstraint(
            "(acquisition_cost_minor_units IS NULL) = (currency IS NULL)",
            name="ck_asset_cost_currency_pair",
        ),
        sa.UniqueConstraint("asset_id", "tenant_id", name="uq_asset_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_assets_tenant_status", "assets", ["tenant_id", "status"], schema=_SCHEMA)

    # -------------------------------------------------------------------- purchase_orders
    op.create_table(
        "purchase_orders",
        sa.Column("po_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("vendor_id", sa.String(64), nullable=False),
        sa.Column("asset_id", sa.String(64), nullable=True),
        sa.Column("description", sa.String(512), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="requested"),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("amount_minor_units >= 0", name="ck_po_amount_nonneg"),
        sa.CheckConstraint("status IN ('requested','approved','rejected')", name="ck_po_status"),
        sa.CheckConstraint(
            "(status = 'requested') = (decided_by IS NULL AND decided_at IS NULL)",
            name="ck_po_decision_consistency",
        ),
        sa.ForeignKeyConstraint(
            ["vendor_id", "tenant_id"],
            [f"{_SCHEMA}.vendors.vendor_id", f"{_SCHEMA}.vendors.tenant_id"],
            name="fk_po_vendor",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "tenant_id"],
            [f"{_SCHEMA}.assets.asset_id", f"{_SCHEMA}.assets.tenant_id"],
            name="fk_po_asset",
        ),
        sa.UniqueConstraint("po_id", "tenant_id", name="uq_po_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_po_tenant_status", "purchase_orders", ["tenant_id", "status"], schema=_SCHEMA
    )
    op.create_index("ix_po_vendor", "purchase_orders", ["vendor_id"], schema=_SCHEMA)

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.vendors TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.assets TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.purchase_orders TO {_APP_ROLE}")

    _enable_rls("vendors", insert=True, update=True)
    _enable_rls("assets", insert=True, update=True)
    _enable_rls("purchase_orders", insert=True, update=True)


def downgrade() -> None:
    for table in ("purchase_orders", "assets", "vendors"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    op.drop_index("ix_po_vendor", table_name="purchase_orders", schema=_SCHEMA)
    op.drop_index("ix_po_tenant_status", table_name="purchase_orders", schema=_SCHEMA)
    op.drop_table("purchase_orders", schema=_SCHEMA)

    op.drop_index("ix_assets_tenant_status", table_name="assets", schema=_SCHEMA)
    op.drop_table("assets", schema=_SCHEMA)

    op.drop_index("ix_vendors_tenant", table_name="vendors", schema=_SCHEMA)
    op.drop_table("vendors", schema=_SCHEMA)
