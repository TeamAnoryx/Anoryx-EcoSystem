"""Delta privacy-first bank-statement import framework (D-025).

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-11

Renumbered from 0017 to 0018 (was originally authored against a main where 0017 was
free): the parallel D-023 track's migration 0017_investment_holdings.py claimed that
revision number first, off the same D-024-based main this migration also started
from. Two independent, uncoordinated sessions computed the same "next" number. No
content in this migration changed, only its revision id and down_revision (now
chains after D-023's 0017 instead of directly after D-024's 0016).

The roadmap's literal Phase-4 text for D-025 is "Privacy-first multi-bank financial
data aggregation." No open-banking connection, bank OAuth credential, or aggregator
API (Plaid/Tink/TrueLayer/...) exists anywhere in this codebase or this environment —
an unattended run cannot responsibly fabricate one. This migration builds the honest
slice (see docs/adr/0025-delta-bank-import.md Sec 1): a privacy-first NORMALIZED
IMPORT framework — caller-supplied bank-statement lines (the same caller-supplied-
line-items shape D-019's ERP sync established) ingested through a generic endpoint,
normalized into D-021's personal ledger (``source='import'``), deduplicated per
source, and audit-chained. The future real-aggregator integration point is named
explicitly: normalize that provider's data into this line shape and POST it through
this same endpoint.

The PRIVACY-FIRST properties are the genuinely buildable core, enforced structurally:

- **Data minimization** — only whitelisted fields exist; there is deliberately NO
  raw-payload JSONB column anywhere in this feature (unlike D-004's DLQ / D-019's
  sync framework, nothing the caller sends but we don't need is ever retained).
- **Dedup by HASH, not raw identifier** — the bank's own transaction reference is
  stored only as ``external_reference_hash`` (SHA-256); equality is all dedup needs,
  so the raw bank-side identifier is never persisted.
- **RLS tenant isolation, append-only** — SELECT/INSERT grants only on all three
  tables; strict fail-closed NULLIF RLS predicate as every prior migration.

Three new tables:

1. ``bank_sources`` — a registered institution feed, linked (composite tenant-scoped
   FK) to the D-021 ``personal_accounts`` row it fills. ``institution_label`` is an
   operator-typed free string ("Chase", "N26") — NOT a live integration, exactly
   like D-019's ``external_systems.vendor_label``.
2. ``statement_imports`` — one row per import run, with write-once counters that
   must sum (same ``ck_*_counts_sum`` shape as D-019's ``sync_runs``).
3. ``imported_statement_lines`` — one row per supplied line and its outcome
   (imported / skipped_duplicate / rejected). The partial unique index on
   ``(source_id, external_reference_hash) WHERE status = 'imported'`` is the dedup
   backstop: one bank transaction imports at most once per source, while a REJECTED
   line's reference stays retryable after the caller fixes it.

Also widens D-021's ``ck_personal_txn_source`` from ``('manual','execution')`` to
``('manual','execution','import')`` — the same designed extension point D-024's
migration 0016 exercised, third value now.

DOWN: drops the three tables (lines, imports, sources — FK dependency order) and
restores the two-value source CHECK. As with 0016, the narrower CHECK re-add fails
loudly if 'import' ledger rows exist rather than deleting tenant data (CI's
migration-roundtrip job runs on an empty database, where this reverses cleanly).
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

# Mirrors migration 0014's _CATEGORIES — an imported statement line may be any
# personal-transaction category, income and transfers included (a real bank
# statement contains salary deposits and inter-account moves).
_CATEGORIES = (
    "('groceries', 'rent', 'utilities', 'dining', 'transport', 'entertainment', "
    "'subscriptions', 'healthcare', 'income', 'transfer', 'other')"
)


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
    # ------------------------------------------------------------------ bank_sources
    op.create_table(
        "bank_sources",
        sa.Column("source_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("institution_label", sa.String(128), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source_id", "tenant_id", name="uq_bank_source_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_bank_source_account",
        "bank_sources",
        "personal_accounts",
        ["account_id", "tenant_id"],
        ["account_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index("ix_bank_sources_tenant", "bank_sources", ["tenant_id"], schema=_SCHEMA)

    # ------------------------------------------------------------- statement_imports
    op.create_table(
        "statement_imports",
        sa.Column("import_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(64), nullable=False),
        sa.Column("imported_by", sa.String(128), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("records_supplied", sa.Integer, nullable=False),
        sa.Column("records_imported", sa.Integer, nullable=False),
        sa.Column("records_skipped_duplicate", sa.Integer, nullable=False),
        sa.Column("records_rejected", sa.Integer, nullable=False),
        sa.CheckConstraint("records_supplied >= 0", name="ck_statement_import_supplied_nonneg"),
        sa.CheckConstraint(
            "records_supplied = records_imported + records_skipped_duplicate + records_rejected",
            name="ck_statement_import_counts_sum",
        ),
        sa.UniqueConstraint("import_id", "tenant_id", name="uq_statement_import_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_statement_import_source",
        "statement_imports",
        "bank_sources",
        ["source_id", "tenant_id"],
        ["source_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    op.create_index(
        "ix_statement_imports_tenant_source",
        "statement_imports",
        ["tenant_id", "source_id"],
        schema=_SCHEMA,
    )

    # -------------------------------------------------------- imported_statement_lines
    op.create_table(
        "imported_statement_lines",
        sa.Column("line_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("import_id", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(64), nullable=False),
        # SHA-256 hex of the bank-side transaction reference — the raw reference is
        # deliberately never stored (privacy-first data minimization, ADR-0025 Fork 2).
        sa.Column("external_reference_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("rejected_reason", sa.String(64), nullable=True),
        sa.Column("txn_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('imported', 'skipped_duplicate', 'rejected')",
            name="ck_imported_line_status",
        ),
        sa.CheckConstraint(
            "(status = 'imported') = (txn_id IS NOT NULL)",
            name="ck_imported_line_txn_consistency",
        ),
        sa.CheckConstraint(
            "(status = 'rejected') = (rejected_reason IS NOT NULL)",
            name="ck_imported_line_reason_consistency",
        ),
        sa.UniqueConstraint("line_id", "tenant_id", name="uq_imported_line_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_imported_line_import",
        "imported_statement_lines",
        "statement_imports",
        ["import_id", "tenant_id"],
        ["import_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    # Dedup backstop: one bank transaction imports at most ONCE per source, while a
    # rejected line's reference stays retryable (partial index excludes non-imported
    # outcomes).
    op.create_index(
        "uq_imported_line_source_ref",
        "imported_statement_lines",
        ["source_id", "external_reference_hash"],
        unique=True,
        schema=_SCHEMA,
        postgresql_where=sa.text("status = 'imported'"),
    )
    op.create_index(
        "ix_imported_lines_tenant_import",
        "imported_statement_lines",
        ["tenant_id", "import_id"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.bank_sources TO {_APP_ROLE}")
    _enable_rls("bank_sources", insert=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.statement_imports TO {_APP_ROLE}")
    _enable_rls("statement_imports", insert=True)

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.imported_statement_lines TO {_APP_ROLE}")
    _enable_rls("imported_statement_lines", insert=True)

    # ---------------------------------------- widen personal_transactions source CHECK
    op.drop_constraint("ck_personal_txn_source", "personal_transactions", schema=_SCHEMA)
    op.create_check_constraint(
        "ck_personal_txn_source",
        "personal_transactions",
        "source IN ('manual', 'execution', 'import')",
        schema=_SCHEMA,
    )


def downgrade() -> None:
    # Restore the two-value source CHECK (fails loudly if 'import' rows exist — see
    # the module docstring; never deletes ledger rows).
    op.drop_constraint("ck_personal_txn_source", "personal_transactions", schema=_SCHEMA)
    op.create_check_constraint(
        "ck_personal_txn_source",
        "personal_transactions",
        "source IN ('manual', 'execution')",
        schema=_SCHEMA,
    )

    op.execute(
        f"DROP POLICY IF EXISTS imported_statement_lines_tenant_insert "
        f"ON {_SCHEMA}.imported_statement_lines"
    )
    op.execute(
        f"DROP POLICY IF EXISTS imported_statement_lines_tenant_select "
        f"ON {_SCHEMA}.imported_statement_lines"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.imported_statement_lines FROM {_APP_ROLE}")
    op.drop_index(
        "ix_imported_lines_tenant_import", table_name="imported_statement_lines", schema=_SCHEMA
    )
    op.drop_index(
        "uq_imported_line_source_ref", table_name="imported_statement_lines", schema=_SCHEMA
    )
    op.drop_constraint(
        "fk_imported_line_import", "imported_statement_lines", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("imported_statement_lines", schema=_SCHEMA)

    op.execute(
        f"DROP POLICY IF EXISTS statement_imports_tenant_insert ON {_SCHEMA}.statement_imports"
    )
    op.execute(
        f"DROP POLICY IF EXISTS statement_imports_tenant_select ON {_SCHEMA}.statement_imports"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.statement_imports FROM {_APP_ROLE}")
    op.drop_index(
        "ix_statement_imports_tenant_source", table_name="statement_imports", schema=_SCHEMA
    )
    op.drop_constraint(
        "fk_statement_import_source", "statement_imports", schema=_SCHEMA, type_="foreignkey"
    )
    op.drop_table("statement_imports", schema=_SCHEMA)

    op.execute(f"DROP POLICY IF EXISTS bank_sources_tenant_insert ON {_SCHEMA}.bank_sources")
    op.execute(f"DROP POLICY IF EXISTS bank_sources_tenant_select ON {_SCHEMA}.bank_sources")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.bank_sources FROM {_APP_ROLE}")
    op.drop_index("ix_bank_sources_tenant", table_name="bank_sources", schema=_SCHEMA)
    op.drop_constraint("fk_bank_source_account", "bank_sources", schema=_SCHEMA, type_="foreignkey")
    op.drop_table("bank_sources", schema=_SCHEMA)
