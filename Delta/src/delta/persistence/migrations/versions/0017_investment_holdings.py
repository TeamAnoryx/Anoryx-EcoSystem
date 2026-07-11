"""Delta personal asset allocation + micro-investment recommendations (D-023,
ADR-0023).

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-11

D-021's own ADR-0021 named this task's job precisely: "No investment/asset-
allocation logic beyond the `investment` account type label. That is D-023's named
job." (ADR-0021 Sec 3). This migration is that job's persistence half.

One new table:

1. ``investment_holdings`` -- a self-reported SNAPSHOT of how much value a
   D-021 `investment`-type account holds in one asset class (stocks / bonds /
   cash_equivalents / real_estate / crypto / other). INSERT-only, mirroring
   D-021's own `personal_budgets` and every D-018+ "simplest possible write
   pattern" table in this codebase: a holding value change is a NEW row for that
   (account_id, asset_class) pair, never an UPDATE -- the store reads the latest
   row per pair. No live market-data/pricing feed of any kind exists anywhere in
   this codebase or this environment (verified before starting this task, same
   dependency check every D-013+ ADR performs up front) -- a holding's value is
   exactly what the caller declares it to be, an honest boundary named verbatim
   in ADR-0023 rather than silently implied away.

No DB-layer CHECK enforces that ``account_id`` resolves to an `investment`-typed
`personal_accounts` row -- that would require a cross-table CHECK subquery, which
Postgres does not support directly; the service layer enforces it explicitly
(mirrors D-021's own `create_transaction`'s explicit account-ownership check
alongside its RLS/FK backstop).

Composite FK to `personal_accounts(account_id, tenant_id)` mirrors D-021 migration
0014's `personal_transactions` -> `personal_accounts` FK exactly.

Grants: `delta_app` gets SELECT, INSERT only -- no UPDATE, no DELETE (every row is
written once and never revised, same grant shape as every insert-only table since
D-018/D-019). Same strict fail-closed NULLIF RLS predicate as every prior migration.

DOWN: drops the table. Retains the `delta` schema and never touches D-001..D-022
data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

_ASSET_CLASSES = "('stocks', 'bonds', 'cash_equivalents', 'real_estate', 'crypto', 'other')"


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
    op.create_table(
        "investment_holdings",
        sa.Column("holding_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("asset_class", sa.String(24), nullable=False),
        sa.Column("value_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"asset_class IN {_ASSET_CLASSES}", name="ck_investment_holding_class"),
        sa.CheckConstraint("value_minor_units >= 0", name="ck_investment_holding_value_nonneg"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_investment_holding_account",
        "investment_holdings",
        "personal_accounts",
        ["account_id", "tenant_id"],
        ["account_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_investment_holdings_tenant", "investment_holdings", ["tenant_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_investment_holdings_tenant_account_class_created",
        "investment_holdings",
        ["tenant_id", "account_id", "asset_class", "created_at"],
        schema=_SCHEMA,
    )

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.investment_holdings TO {_APP_ROLE}")
    _enable_rls("investment_holdings", insert=True)


def downgrade() -> None:
    op.execute(
        f"DROP POLICY IF EXISTS investment_holdings_tenant_insert ON {_SCHEMA}.investment_holdings"
    )
    op.execute(
        f"DROP POLICY IF EXISTS investment_holdings_tenant_select ON {_SCHEMA}.investment_holdings"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.investment_holdings FROM {_APP_ROLE}")
    op.drop_index(
        "ix_investment_holdings_tenant_account_class_created",
        table_name="investment_holdings",
        schema=_SCHEMA,
    )
    op.drop_index("ix_investment_holdings_tenant", table_name="investment_holdings", schema=_SCHEMA)
    op.drop_constraint(
        "fk_investment_holding_account",
        "investment_holdings",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_table("investment_holdings", schema=_SCHEMA)
