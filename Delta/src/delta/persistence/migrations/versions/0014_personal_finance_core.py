"""Delta personal-finance core: accounts, transactions, budgets (D-021, B2C track).

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-10

D-021 is the first task in the B2C personal-finance track (D-021->D-025), which the
roadmap says "Depends on: D-003 + the B2C onboarding shell." Neither dependency
exists as stated: no B2C consumer identity/signup/auth model has been built anywhere
in this ecosystem (verified before starting this arc — Rendly's R-023 "Consumer
onboarding" explicitly disclaims building one, see its own ADR-0023), and D-003's
`ledger_entries` bakes in AI-usage-specific `team_id`/`project_id`/`agent_id` NOT NULL
columns that have no meaning for a person's grocery purchase. ADR-0021 resolves both
gaps the same way every D-013+ task resolved an unbuildable stated dependency: name
the real gap, build the honest bounded slice on top of what DOES exist.

- Fork 1: a B2C consumer IS one `tenant_id` here — reuses D-001's existing
  multi-tenant RLS scoping boundary (already just an opaque UUID, no B2B semantics
  baked into its type), rather than building a new consumer-identity/signup/auth
  model (a legitimately large, separate unit of work, explicitly named as still
  deferred future work, not a hidden prerequisite silently skipped).
- Fork 2: a NEW, structurally separate personal-finance schema, not a reuse of
  D-003's `accounts`/`transactions`/`ledger_entries`. `accounts`/`transactions` ARE
  generic enough to reuse verbatim, but `ledger_entries` requires
  `team_id`/`project_id`/`agent_id` (AI-cost-tracking dimensions) — jamming a
  grocery purchase through that shape would be a semantic corruption of the AI-cost
  ledger every D-013+ package has deliberately stayed out of. Personal transactions
  are single-entry (one signed amount, category-tagged) — matches how real
  personal-finance apps model this, not general-ledger double-entry bookkeeping.

Three new tables:

1. ``personal_accounts`` -- a person's own accounts (checking/savings/credit_card/
   cash/investment), operator/user-declared, currency-tagged.
2. ``personal_transactions`` -- one signed amount per row (negative = expense,
   positive = income), category-tagged, against one account. ``source`` distinguishes
   how the row was created ('manual' only in this migration -- D-024's internal
   execution path and D-025's aggregation-ingestion path each widen this CHECK
   constraint in their own migration when they add their own source, not
   speculatively here).
3. ``personal_budgets`` -- a per-category monthly cap. Insert-only, like every
   INSERT-only table in this codebase since D-018/D-019's "simplest possible write
   pattern" precedent: a budget change is a NEW row for that category+period, not an
   UPDATE -- the store reads the latest row per category (ORDER BY created_at DESC).

No FK from `personal_transactions` to `personal_accounts`'s composite
(account_id, tenant_id) is added at the DB layer beyond the implicit tenant scoping --
mirrors D-018/D-019's existing precedent (composite tenant-scoped FK IS added here,
consistent with every other D-013+ child-table pattern; see below).

Grants: `delta_app` gets SELECT, INSERT only on all three tables -- no UPDATE, no
DELETE anywhere in this migration (every row is written once and never revised, same
grant shape as D-019's tables). Same strict fail-closed NULLIF RLS predicate as every
prior migration.

DOWN: drops all three tables (transactions, then budgets, then accounts -- FK
dependency order). Retains the `delta` schema and never touches D-001..D-020 data.
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

_ACCOUNT_TYPES = "('checking', 'savings', 'credit_card', 'cash', 'investment')"
_CATEGORIES = (
    "('groceries', 'rent', 'utilities', 'dining', 'transport', 'entertainment', "
    "'subscriptions', 'healthcare', 'income', 'transfer', 'other')"
)
_BUDGET_PERIODS = "('monthly')"


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
    # ------------------------------------------------------------------- personal_accounts
    op.create_table(
        "personal_accounts",
        sa.Column("account_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"type IN {_ACCOUNT_TYPES}", name="ck_personal_account_type"),
        sa.UniqueConstraint("account_id", "tenant_id", name="uq_personal_account_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_personal_accounts_tenant", "personal_accounts", ["tenant_id"], schema=_SCHEMA
    )

    # --------------------------------------------------------------- personal_transactions
    op.create_table(
        "personal_transactions",
        sa.Column("txn_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("merchant", sa.String(256), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.CheckConstraint(f"category IN {_CATEGORIES}", name="ck_personal_txn_category"),
        sa.CheckConstraint("amount_minor_units != 0", name="ck_personal_txn_amount_nonzero"),
        sa.CheckConstraint("source IN ('manual')", name="ck_personal_txn_source"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_personal_txn_account",
        "personal_transactions",
        "personal_accounts",
        ["account_id", "tenant_id"],
        ["account_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_personal_transactions_tenant", "personal_transactions", ["tenant_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_personal_transactions_tenant_account",
        "personal_transactions",
        ["tenant_id", "account_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_personal_transactions_tenant_category_occurred",
        "personal_transactions",
        ["tenant_id", "category", "occurred_at"],
        schema=_SCHEMA,
    )

    # -------------------------------------------------------------------- personal_budgets
    op.create_table(
        "personal_budgets",
        sa.Column("budget_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("cap_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("period", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"category IN {_CATEGORIES}", name="ck_personal_budget_category"),
        sa.CheckConstraint("cap_minor_units > 0", name="ck_personal_budget_cap_positive"),
        sa.CheckConstraint(f"period IN {_BUDGET_PERIODS}", name="ck_personal_budget_period"),
        schema=_SCHEMA,
    )
    op.create_index("ix_personal_budgets_tenant", "personal_budgets", ["tenant_id"], schema=_SCHEMA)
    op.create_index(
        "ix_personal_budgets_tenant_category_created",
        "personal_budgets",
        ["tenant_id", "category", "created_at"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.personal_accounts TO {_APP_ROLE}")
    _enable_rls("personal_accounts", insert=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.personal_transactions TO {_APP_ROLE}")
    _enable_rls("personal_transactions", insert=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.personal_budgets TO {_APP_ROLE}")
    _enable_rls("personal_budgets", insert=True)


def downgrade() -> None:
    op.execute(
        f"DROP POLICY IF EXISTS personal_budgets_tenant_insert ON {_SCHEMA}.personal_budgets"
    )
    op.execute(
        f"DROP POLICY IF EXISTS personal_budgets_tenant_select ON {_SCHEMA}.personal_budgets"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.personal_budgets FROM {_APP_ROLE}")
    op.drop_index(
        "ix_personal_budgets_tenant_category_created", table_name="personal_budgets", schema=_SCHEMA
    )
    op.drop_index("ix_personal_budgets_tenant", table_name="personal_budgets", schema=_SCHEMA)
    op.drop_table("personal_budgets", schema=_SCHEMA)

    op.execute(
        f"DROP POLICY IF EXISTS personal_transactions_tenant_insert "
        f"ON {_SCHEMA}.personal_transactions"
    )
    op.execute(
        f"DROP POLICY IF EXISTS personal_transactions_tenant_select "
        f"ON {_SCHEMA}.personal_transactions"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.personal_transactions FROM {_APP_ROLE}")
    op.drop_index(
        "ix_personal_transactions_tenant_category_occurred",
        table_name="personal_transactions",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_personal_transactions_tenant_account",
        table_name="personal_transactions",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_personal_transactions_tenant", table_name="personal_transactions", schema=_SCHEMA
    )
    op.drop_constraint(
        "fk_personal_txn_account", "personal_transactions", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("personal_transactions", schema=_SCHEMA)

    op.execute(
        f"DROP POLICY IF EXISTS personal_accounts_tenant_insert ON {_SCHEMA}.personal_accounts"
    )
    op.execute(
        f"DROP POLICY IF EXISTS personal_accounts_tenant_select ON {_SCHEMA}.personal_accounts"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.personal_accounts FROM {_APP_ROLE}")
    op.drop_index("ix_personal_accounts_tenant", table_name="personal_accounts", schema=_SCHEMA)
    op.drop_table("personal_accounts", schema=_SCHEMA)
