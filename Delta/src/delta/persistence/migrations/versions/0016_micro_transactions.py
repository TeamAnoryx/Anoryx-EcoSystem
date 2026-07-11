"""Delta real-time personal micro-transaction execution log (D-024).

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-11

The roadmap's literal Phase-4 text for D-024 is "Real-time secure personal
micro-transaction execution." No payment rail, card network, bank connection, or
external money-movement integration of any kind exists anywhere in this codebase
(D-025, the multi-bank aggregation task, is itself still unbuilt) — see
docs/adr/0024-delta-micro-transaction-execution.md Sec 1 for the full honesty
boundary. This migration builds the honest slice: a synchronous, idempotent,
safety-capped execution engine over Delta's OWN D-021 personal-finance ledger.
"Executing" a micro-transaction here means atomically (a) recording the execution
decision in the append-only ``micro_transaction_executions`` log, (b) writing the
corresponding D-021 ``personal_transactions`` ledger row (source='execution'), and
(c) appending a D-009 hash-chain audit row — all in ONE database transaction. It
does NOT move real money.

Changes:

1. New table ``micro_transaction_executions`` — one row per execution ATTEMPT,
   executed or rejected (recording rejected attempts is itself a security feature:
   a capped-out or replayed attempt leaves a trace). Append-only: SELECT/INSERT
   grant only, no UPDATE/DELETE (mirrors D-018's ``invoice_payments``/D-022's
   ``subscription_charges``). ``UNIQUE (tenant_id, idempotency_key)`` is the
   idempotency backstop — the service layer returns the stored original result on
   replay, and this constraint makes a double-insert race structurally impossible.
2. ``ck_personal_txn_source`` on D-021's ``personal_transactions`` is widened from
   ``('manual')`` to ``('manual', 'execution')`` so an executed micro-transaction
   lands in the same personal ledger every D-021 read (budgets, health score,
   category spend) already consumes — an executed payment that were invisible to
   the owner's own budget tracking would be a dishonest ledger. The ``source``
   column + CHECK were D-021's own designed extension point for exactly this
   (a one-value vocabulary named ``TransactionSource``).

DOWN: drops ``micro_transaction_executions`` and restores the original one-value
source CHECK. NOTE: the downgrade's narrower CHECK re-add fails by design if any
``source='execution'`` rows exist — deleting a tenant's real ledger rows in a
schema downgrade would be worse than failing loudly (CI's migration-roundtrip job
runs on an empty database, where this reverses cleanly).
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

# Mirrors migration 0014's _CATEGORIES minus 'income' (an executed micro-transaction
# is a payment — an expense — never an income event).
_EXECUTION_CATEGORIES = (
    "('groceries', 'rent', 'utilities', 'dining', 'transport', 'entertainment', "
    "'subscriptions', 'healthcare', 'transfer', 'other')"
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
    # -------------------------------------------------- micro_transaction_executions
    op.create_table(
        "micro_transaction_executions",
        sa.Column("execution_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("merchant", sa.String(256), nullable=True),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("rejection_reason", sa.String(64), nullable=True),
        sa.Column("txn_id", sa.String(64), nullable=True),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        # The magnitude to pay, always positive — the ledger row it produces carries
        # the negative (expense) sign, following D-021's signed-amount convention.
        sa.CheckConstraint("amount_minor_units > 0", name="ck_micro_txn_execution_amount_positive"),
        sa.CheckConstraint(
            "status IN ('executed', 'rejected')", name="ck_micro_txn_execution_status"
        ),
        sa.CheckConstraint(
            f"category IN {_EXECUTION_CATEGORIES}", name="ck_micro_txn_execution_category"
        ),
        # A row is executed iff it produced a ledger row; rejected iff it carries a
        # reason — the two outcomes are structurally mutually exclusive.
        sa.CheckConstraint(
            "(status = 'executed') = (txn_id IS NOT NULL)",
            name="ck_micro_txn_execution_txn_consistency",
        ),
        sa.CheckConstraint(
            "(status = 'rejected') = (rejection_reason IS NOT NULL)",
            name="ck_micro_txn_execution_reason_consistency",
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_micro_txn_execution_idempotency"
        ),
        sa.UniqueConstraint("execution_id", "tenant_id", name="uq_micro_txn_execution_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_foreign_key(
        "fk_micro_txn_execution_account",
        "micro_transaction_executions",
        "personal_accounts",
        ["account_id", "tenant_id"],
        ["account_id", "tenant_id"],
        source_schema=_SCHEMA,
        referent_schema=_SCHEMA,
    )
    # Supports the rolling daily-cap sum: executed rows for one account by time.
    op.create_index(
        "ix_micro_txn_executions_account_executed_at",
        "micro_transaction_executions",
        ["account_id", "executed_at"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_micro_txn_executions_tenant",
        "micro_transaction_executions",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.micro_transaction_executions TO {_APP_ROLE}")
    _enable_rls("micro_transaction_executions", insert=True)

    # -------------------------------------- widen personal_transactions source CHECK
    op.drop_constraint("ck_personal_txn_source", "personal_transactions", schema=_SCHEMA)
    op.create_check_constraint(
        "ck_personal_txn_source",
        "personal_transactions",
        "source IN ('manual', 'execution')",
        schema=_SCHEMA,
    )


def downgrade() -> None:
    # Restore the original one-value source CHECK (fails loudly if 'execution' rows
    # exist — see the module docstring; never deletes ledger rows).
    op.drop_constraint("ck_personal_txn_source", "personal_transactions", schema=_SCHEMA)
    op.create_check_constraint(
        "ck_personal_txn_source",
        "personal_transactions",
        "source IN ('manual')",
        schema=_SCHEMA,
    )

    op.execute(
        f"DROP POLICY IF EXISTS micro_transaction_executions_tenant_insert "
        f"ON {_SCHEMA}.micro_transaction_executions"
    )
    op.execute(
        f"DROP POLICY IF EXISTS micro_transaction_executions_tenant_select "
        f"ON {_SCHEMA}.micro_transaction_executions"
    )
    op.execute(f"REVOKE ALL ON {_SCHEMA}.micro_transaction_executions FROM {_APP_ROLE}")

    op.drop_index(
        "ix_micro_txn_executions_tenant",
        table_name="micro_transaction_executions",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_micro_txn_executions_account_executed_at",
        table_name="micro_transaction_executions",
        schema=_SCHEMA,
    )
    op.drop_constraint(
        "fk_micro_txn_execution_account",
        "micro_transaction_executions",
        schema=_SCHEMA,
        type_="foreignkey",
    )
    op.drop_table("micro_transaction_executions", schema=_SCHEMA)
