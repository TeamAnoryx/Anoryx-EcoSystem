"""Delta recurring-subscription registry + charge ledger (D-022).

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-11

The roadmap's literal Phase-4 framing for D-021..D-025 is a B2C personal-finance
track ("Depends on: D-003 + the B2C onboarding shell"). No B2C onboarding shell, no
personal/individual account model, and no bank-linking of any kind exists anywhere in
this codebase (D-025, the multi-bank aggregation task, is itself still unbuilt) — see
docs/adr/0021-delta-subscription-anomaly-alerts.md Sec 1 for the full honesty
boundary. This migration instead builds D-022's title ("Automated subscription
management + anomalous-charge alerts") as an ENTERPRISE-tenant feature on Delta's
existing tenant/vendor model: a recurring-subscription registry (optionally linked to
a D-014 vendor) plus an append-only ledger of each billing occurrence, so
``delta.chargeback.anomaly.detect_anomalies`` (D-012, unmodified) can flag a charge
that is an outlier against that subscription's own trailing history.

Two new tables:

1. ``subscriptions`` — one row per tracked recurring commitment. ``status`` moves
   forward only (active -> cancelled), enforced at the app layer
   (delta.subscriptions.service), mirrors D-014's asset-lifecycle decision (not a DB
   CHECK, since the actual invariant is "no reverse transition," not a closed
   vocabulary). ``vendor_id`` is an OPTIONAL composite FK to D-014's ``vendors`` — a
   subscription need not correspond to a tracked vendor.
2. ``subscription_charges`` — append-only ledger of billing occurrences against a
   subscription. No UPDATE/DELETE grant (mirrors D-018's ``invoice_payments`` /
   D-019's ``sync_line_items``): a charge, once recorded, is never revised — a
   correction is a new charge row, not an edit to history.

Grants: ``delta_app`` gets SELECT/INSERT/UPDATE on ``subscriptions`` (status
transitions), SELECT/INSERT only on ``subscription_charges`` (append-only) — never
DELETE on either. Same strict fail-closed NULLIF RLS predicate as every prior
migration.

DOWN: reverses every object in dependency order (charges before subscriptions).
Retains the ``delta`` schema and never touches D-001..D-019 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
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
    # ---------------------------------------------------------------------- subscriptions
    op.create_table(
        "subscriptions",
        sa.Column("subscription_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("vendor_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("expected_amount_minor_units", sa.BigInteger, nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("cadence", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "cadence IN ('weekly','monthly','quarterly','annual')", name="ck_subscription_cadence"
        ),
        sa.CheckConstraint("status IN ('active','cancelled')", name="ck_subscription_status"),
        sa.CheckConstraint(
            "(expected_amount_minor_units IS NULL) = (currency IS NULL)",
            name="ck_subscription_expected_amount_currency_pair",
        ),
        sa.CheckConstraint(
            "expected_amount_minor_units IS NULL OR expected_amount_minor_units >= 0",
            name="ck_subscription_expected_amount_nonneg",
        ),
        sa.CheckConstraint(
            "(status = 'active') = (cancelled_at IS NULL)",
            name="ck_subscription_cancelled_at_consistency",
        ),
        sa.UniqueConstraint("subscription_id", "tenant_id", name="uq_subscription_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_subscription_vendor",
        "subscriptions",
        "vendors",
        ["vendor_id", "tenant_id"],
        ["vendor_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_subscriptions_tenant_status", "subscriptions", ["tenant_id", "status"], schema=_SCHEMA
    )

    # ----------------------------------------------------------------- subscription_charges
    op.create_table(
        "subscription_charges",
        sa.Column("charge_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("subscription_id", sa.String(64), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("charged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_by", sa.String(128), nullable=False),
        sa.Column("note", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount_minor_units >= 0", name="ck_subscription_charge_amount_nonneg"),
        sa.UniqueConstraint("charge_id", "tenant_id", name="uq_subscription_charge_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_subscription_charge_subscription",
        "subscription_charges",
        "subscriptions",
        ["subscription_id", "tenant_id"],
        ["subscription_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_subscription_charges_tenant_sub",
        "subscription_charges",
        ["tenant_id", "subscription_id"],
        schema=_SCHEMA,
    )
    # Supports the windowed "most recent N charges per subscription" query
    # (delta.subscriptions.store.list_recent_charges_by_subscription) without a scan.
    op.create_index(
        "ix_subscription_charges_sub_charged_at",
        "subscription_charges",
        ["subscription_id", sa.text("charged_at DESC")],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.subscriptions TO {_APP_ROLE}")
    _enable_rls("subscriptions", insert=True, update=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.subscription_charges TO {_APP_ROLE}")
    _enable_rls("subscription_charges", insert=True, update=False)


def downgrade() -> None:
    op.execute(
        f"DROP POLICY IF EXISTS subscription_charges_tenant_insert "
        f"ON {_SCHEMA}.subscription_charges"
    )
    op.execute(
        f"DROP POLICY IF EXISTS subscription_charges_tenant_select "
        f"ON {_SCHEMA}.subscription_charges"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.subscription_charges FROM {_APP_ROLE}")

    op.drop_index(
        "ix_subscription_charges_sub_charged_at",
        table_name="subscription_charges",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_subscription_charges_tenant_sub", table_name="subscription_charges", schema=_SCHEMA
    )
    op.drop_constraint(
        "fk_subscription_charge_subscription",
        "subscription_charges",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_table("subscription_charges", schema=_SCHEMA)

    op.execute(f"DROP POLICY IF EXISTS subscriptions_tenant_update ON {_SCHEMA}.subscriptions")
    op.execute(f"DROP POLICY IF EXISTS subscriptions_tenant_insert ON {_SCHEMA}.subscriptions")
    op.execute(f"DROP POLICY IF EXISTS subscriptions_tenant_select ON {_SCHEMA}.subscriptions")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.subscriptions FROM {_APP_ROLE}")

    op.drop_index("ix_subscriptions_tenant_status", table_name="subscriptions", schema=_SCHEMA)
    op.drop_constraint(
        "fk_subscription_vendor", "subscriptions", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("subscriptions", schema=_SCHEMA)
