"""Delta personal asset-allocation recommendation history (D-023, B2C track).

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-11

D-021's ADR (docs/adr/0021-delta-personal-finance-budget-tracking.md, Sec 3) named this
task's job explicitly: "no investment/asset-allocation logic beyond the `investment`
account type label" — D-021 shipped the label, D-023 builds on top of it. Same honest
scope as D-021/D-022: no B2C onboarding shell, no bank-linking, no real brokerage/market
integration exists anywhere in this codebase (D-024/D-025 remain unbuilt) — see
docs/adr/0023-delta-asset-allocation-recommendations.md Sec 1.

One new table:

``personal_allocation_recommendations`` -- an append-only history of computed
recommendations against a `personal_accounts` row of type "investment". Each row is a
DETERMINISTIC, rules-based target-allocation percentage split (cash/bonds/equities) for
one of three fixed risk tiers, plus a recommended one-time micro-investment amount
(a fixed percentage of the tenant's net income-minus-expense surplus over a
caller-specified window, floored to 0 whenever that surplus is not positive). No ML, no
live market data, no real money movement — see the ADR for the full honesty boundary.

Append-only (mirrors D-022's ``subscription_charges``): ``delta_app`` gets SELECT,
INSERT only -- no UPDATE, no DELETE. A recommendation, once computed, is a historical
record; a new computation is always a new row.

DOWN: drops the table. Retains the `delta` schema and never touches D-001..D-022 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"
_RISK_TIERS = "('conservative', 'moderate', 'aggressive')"


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {table}_tenant_select ON {_SCHEMA}.{table} "
        f"FOR SELECT USING ({_TENANT_PREDICATE})"
    )
    op.execute(
        f"CREATE POLICY {table}_tenant_insert ON {_SCHEMA}.{table} "
        f"FOR INSERT WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    op.create_table(
        "personal_allocation_recommendations",
        sa.Column("recommendation_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("risk_tier", sa.String(16), nullable=False),
        sa.Column("cash_pct", sa.SmallInteger, nullable=False),
        sa.Column("bonds_pct", sa.SmallInteger, nullable=False),
        sa.Column("equities_pct", sa.SmallInteger, nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("surplus_minor_units", sa.BigInteger, nullable=False),
        sa.Column("recommended_micro_investment_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("method", sa.String(32), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"risk_tier IN {_RISK_TIERS}", name="ck_allocation_rec_risk_tier"),
        sa.CheckConstraint(
            "cash_pct >= 0 AND bonds_pct >= 0 AND equities_pct >= 0",
            name="ck_allocation_rec_pct_nonneg",
        ),
        sa.CheckConstraint(
            "cash_pct + bonds_pct + equities_pct = 100", name="ck_allocation_rec_pct_sums_100"
        ),
        sa.CheckConstraint("period_end > period_start", name="ck_allocation_rec_period_order"),
        sa.CheckConstraint(
            "recommended_micro_investment_minor_units >= 0",
            name="ck_allocation_rec_micro_investment_nonneg",
        ),
        sa.UniqueConstraint("recommendation_id", "tenant_id", name="uq_allocation_rec_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_allocation_rec_account",
        "personal_allocation_recommendations",
        "personal_accounts",
        ["account_id", "tenant_id"],
        ["account_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_allocation_rec_tenant_account_computed",
        "personal_allocation_recommendations",
        ["tenant_id", "account_id", sa.text("computed_at DESC")],
        schema=_SCHEMA,
    )

    op.execute(
        f"GRANT SELECT, INSERT ON {_SCHEMA}.personal_allocation_recommendations " f"TO {_APP_ROLE}"
    )
    _enable_rls("personal_allocation_recommendations")


def downgrade() -> None:
    op.execute(
        f"DROP POLICY IF EXISTS personal_allocation_recommendations_tenant_insert "
        f"ON {_SCHEMA}.personal_allocation_recommendations"
    )
    op.execute(
        f"DROP POLICY IF EXISTS personal_allocation_recommendations_tenant_select "
        f"ON {_SCHEMA}.personal_allocation_recommendations"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.personal_allocation_recommendations FROM {_APP_ROLE}")
    op.drop_index(
        "ix_allocation_rec_tenant_account_computed",
        table_name="personal_allocation_recommendations",
        schema=_SCHEMA,
    )
    op.drop_constraint(
        "fk_allocation_rec_account",
        "personal_allocation_recommendations",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_table("personal_allocation_recommendations", schema=_SCHEMA)
