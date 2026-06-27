"""Delta double-entry ledger: schema, tables, RLS, delta_app role, append-only +
deferred balanced-constraint enforcement (D-003).

Revision ID: 0001
Revises:
Create Date: 2026-06-26

This is the FIRST Delta DDL. It creates the authoritative ledger in the ``delta``
schema (ADR-0003 Fork 4) with the database — not the application — as the authority
for ledger correctness:

1. Tables: delta.accounts, delta.transactions, delta.ledger_entries. Money is BIGINT
   integer cents only (no float / NUMERIC anywhere — ADR-0003).

2. Double-entry enforcement (Fork 1): a DEFERRABLE INITIALLY DEFERRED constraint
   trigger on ledger_entries re-aggregates the full entry set per txn at COMMIT and
   rejects unless SUM(signed)=0, count>=2, one currency, one tenant == parent txn.
   Even a direct single unbalanced INSERT aborts at COMMIT.

3. Append-only (no UPDATE/DELETE ever): a BEFORE UPDATE/DELETE trigger RAISEs on all
   three tables; RLS USING(false) for UPDATE/DELETE; delta_app granted only
   SELECT+INSERT. Reversal is a NEW compensating transaction (reversal_of), never a
   mutation.

4. RLS: ENABLE + FORCE on every table with the strict NULLIF predicate
   (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')) for
   SELECT (USING) and INSERT (WITH CHECK) — fail-closed on unset/empty GUC.

5. delta_app role: created idempotently with NO password in SQL (the secrets rule).
   The SCRAM password is provisioned out-of-band by the entrypoint POST-migrate
   (DELTA_PROVISION_APP_ROLE=1) — see Delta/docker-entrypoint.sh. A passwordless role
   is the migration-0006 defect; the entrypoint fix is what makes a fresh `compose
   up` authenticate. For LOCAL DEV without the entrypoint:
       ALTER ROLE delta_app WITH PASSWORD 'your_local_dev_password';

6. Idempotency (Fork 5): partial UNIQUE (tenant_id, idempotency_key) so D-004's
   event ingest is idempotent at the ledger (one replayed event = one debit).

DOWN: reverses every object in dependency order (triggers, functions, policies,
grants, tables, role-if-unowned). It deliberately does NOT drop the `delta` schema —
that schema houses the alembic_version table. Never touches tenant data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

# The strict fail-closed RLS predicate (identical in shape to F-003b Option α).
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# The largest monetary value any wire contract carries (D-001 MAX_MONEY_MINOR_UNITS).
_MAX_MINOR_UNITS = 100_000_000_000  # 1e11 cents


def _enable_rls(table: str) -> None:
    """ENABLE + FORCE RLS and create per-command policies on a delta table.

    SELECT/INSERT are tenant-scoped; UPDATE/DELETE are unsatisfiable (append-only).
    """
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
    # Append-only: no row is ever eligible for UPDATE or DELETE.
    op.execute(f"CREATE POLICY {table}_deny_update ON {_SCHEMA}.{table} FOR UPDATE USING (false)")
    op.execute(f"CREATE POLICY {table}_deny_delete ON {_SCHEMA}.{table} FOR DELETE USING (false)")


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}")

    # ------------------------------------------------------------------ accounts
    op.create_table(
        "accounts",
        sa.Column("account_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.CheckConstraint(
            "type IN ('asset','liability','equity','revenue','expense')",
            name="ck_accounts_type",
        ),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="ck_accounts_currency"),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 256", name="ck_accounts_name_len"),
        schema=_SCHEMA,
    )
    op.create_index("ix_accounts_tenant", "accounts", ["tenant_id"], schema=_SCHEMA)

    # -------------------------------------------------------------- transactions
    op.create_table(
        "transactions",
        sa.Column("txn_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        # The compensating-transaction link (reversal). Self-referential; nullable.
        sa.Column(
            "reversal_of",
            sa.String(64),
            sa.ForeignKey(f"{_SCHEMA}.transactions.txn_id", name="fk_txn_reversal_of"),
            nullable=True,
        ),
        sa.Column("idempotency_key", sa.String(255), nullable=True),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="ck_txn_currency"),
        sa.CheckConstraint(
            "reversal_of IS NULL OR reversal_of <> txn_id", name="ck_txn_no_self_rev"
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_txn_tenant", "transactions", ["tenant_id"], schema=_SCHEMA)
    # Fork 5: idempotency dedup — one (tenant, key) at most, only when a key is given.
    op.create_index(
        "ux_txn_idempotency",
        "transactions",
        ["tenant_id", "idempotency_key"],
        schema=_SCHEMA,
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    # ------------------------------------------------------------ ledger_entries
    op.create_table(
        "ledger_entries",
        sa.Column("entry_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "txn_id",
            sa.String(64),
            sa.ForeignKey(f"{_SCHEMA}.transactions.txn_id", name="fk_entry_txn"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("direction", sa.String(8), nullable=False),
        # Money: BIGINT integer cents only. No float / NUMERIC in the money path.
        sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("team_id", sa.String(64), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("direction IN ('debit','credit')", name="ck_entry_direction"),
        sa.CheckConstraint(
            f"amount_minor_units >= 0 AND amount_minor_units <= {_MAX_MINOR_UNITS}",
            name="ck_entry_amount_bounds",
        ),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="ck_entry_currency"),
        schema=_SCHEMA,
    )
    # Balance scans (point-in-time + windowed) read by (tenant, account, time).
    op.create_index(
        "ix_entry_tenant_account_ts",
        "ledger_entries",
        ["tenant_id", "account_id", "timestamp"],
        schema=_SCHEMA,
    )
    # The deferred balanced check re-aggregates by txn_id.
    op.create_index("ix_entry_txn", "ledger_entries", ["txn_id"], schema=_SCHEMA)

    # ------------------------------------------------ double-entry enforcement
    # Fork 1: deferred constraint trigger. At COMMIT, the full entry set of each
    # touched txn must SUM(signed)=0, count>=2, one currency, one tenant == parent.
    # SECURITY INVOKER (default): runs as the inserting role under its RLS context;
    # all of a txn's entries are the GUC tenant (WITH CHECK enforces this at INSERT),
    # so the aggregate sees the complete set. An unset GUC collapses the view to zero
    # rows -> count<2 -> RAISE (fail-closed).
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_SCHEMA}.assert_txn_balanced()
        RETURNS TRIGGER AS $$
        DECLARE
            v_debit   BIGINT;
            v_credit  BIGINT;
            v_count   INTEGER;
            v_curr    INTEGER;
            v_tenants INTEGER;
            v_entry_tenant   {_SCHEMA}.ledger_entries.tenant_id%TYPE;
            v_entry_currency {_SCHEMA}.ledger_entries.currency%TYPE;
            v_txn_tenant     {_SCHEMA}.transactions.tenant_id%TYPE;
            v_txn_currency   {_SCHEMA}.transactions.currency%TYPE;
        BEGIN
            SELECT
                COALESCE(SUM(amount_minor_units) FILTER (WHERE direction = 'debit'), 0),
                COALESCE(SUM(amount_minor_units) FILTER (WHERE direction = 'credit'), 0),
                COUNT(*),
                COUNT(DISTINCT currency),
                COUNT(DISTINCT tenant_id),
                MIN(tenant_id),
                MIN(currency)
            INTO v_debit, v_credit, v_count, v_curr, v_tenants, v_entry_tenant, v_entry_currency
            FROM {_SCHEMA}.ledger_entries
            WHERE txn_id = NEW.txn_id;

            IF v_count < 2 THEN
                RAISE EXCEPTION
                    'delta ledger: transaction % has % entries (a double-entry needs >= 2)',
                    NEW.txn_id, v_count;
            END IF;
            IF v_curr <> 1 THEN
                RAISE EXCEPTION
                    'delta ledger: mixed-currency transaction % rejected', NEW.txn_id;
            END IF;
            IF v_tenants <> 1 THEN
                RAISE EXCEPTION
                    'delta ledger: cross-tenant transaction % rejected', NEW.txn_id;
            END IF;
            IF v_debit <> v_credit THEN
                RAISE EXCEPTION
                    'delta ledger: unbalanced transaction %: debits % != credits %',
                    NEW.txn_id, v_debit, v_credit;
            END IF;

            SELECT tenant_id, currency INTO v_txn_tenant, v_txn_currency
            FROM {_SCHEMA}.transactions WHERE txn_id = NEW.txn_id;
            IF v_txn_tenant IS NULL THEN
                RAISE EXCEPTION
                    'delta ledger: orphan entry — transaction % does not exist', NEW.txn_id;
            END IF;
            IF v_txn_tenant <> v_entry_tenant THEN
                RAISE EXCEPTION
                    'delta ledger: entry tenant != transaction tenant for %', NEW.txn_id;
            END IF;
            IF v_txn_currency <> v_entry_currency THEN
                RAISE EXCEPTION
                    'delta ledger: entry currency % != transaction currency % for %',
                    v_entry_currency, v_txn_currency, NEW.txn_id;
            END IF;

            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute(f"""
        CREATE CONSTRAINT TRIGGER trg_le_balanced
        AFTER INSERT ON {_SCHEMA}.ledger_entries
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.assert_txn_balanced();
        """)

    # ------------------------------------------------ committed-txn immutability
    # An entry may only be inserted in the SAME DB transaction that created its
    # parent transaction row. Otherwise a tenant with the (legitimate) INSERT grant
    # could append a *balanced* pair of new entries to an ALREADY-COMMITTED txn —
    # the deferred re-sum stays zero, so the amendment would slip through and mutate
    # a committed transaction's entry set. We compare the parent row's xmin to the
    # current xid in 64-bit space: the parent's xmin (a 32-bit xid) cast to bigint
    # vs txid_current() masked to its low 32 bits. (A naive `txid_current()::text::xid`
    # is NOT epoch-safe — it raises once the xid epoch >= 1 — so we mask instead.)
    # A legitimate append sees the parent row's xmin == this transaction's xid; a
    # later amendment sees a different (committed) xid and is rejected at INSERT.
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_SCHEMA}.assert_entry_in_txn_creation()
        RETURNS TRIGGER AS $$
        DECLARE v_xmin xid;
        BEGIN
            SELECT xmin INTO v_xmin
            FROM {_SCHEMA}.transactions WHERE txn_id = NEW.txn_id;
            IF v_xmin IS NULL THEN
                RAISE EXCEPTION
                    'delta ledger: orphan entry — transaction % does not exist', NEW.txn_id;
            END IF;
            IF v_xmin::text::bigint <> (txid_current() & 4294967295) THEN
                RAISE EXCEPTION
                    'delta ledger: cannot add entries to an already-committed transaction %',
                    NEW.txn_id;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute(f"""
        CREATE TRIGGER trg_le_in_txn_creation
        BEFORE INSERT ON {_SCHEMA}.ledger_entries
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.assert_entry_in_txn_creation();
        """)

    # -------------------------------------------------------- append-only guard
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_SCHEMA}.deny_ledger_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION
                'delta ledger is append-only: % on %.% is forbidden',
                TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """)
    for table in ("accounts", "transactions", "ledger_entries"):
        op.execute(f"""
            CREATE TRIGGER trg_{table}_deny_update
            BEFORE UPDATE ON {_SCHEMA}.{table}
            FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.deny_ledger_modification();
            """)
        op.execute(f"""
            CREATE TRIGGER trg_{table}_deny_delete
            BEFORE DELETE ON {_SCHEMA}.{table}
            FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.deny_ledger_modification();
            """)

    # ----------------------------------------------------- delta_app role + grants
    # Idempotent; NO password in SQL (secrets rule). The entrypoint provisions the
    # SCRAM password POST-migrate (DELTA_PROVISION_APP_ROLE=1).
    op.execute(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{_APP_ROLE}') THEN
                CREATE ROLE {_APP_ROLE}
                    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$;
        """)
    op.execute(f"GRANT USAGE ON SCHEMA {_SCHEMA} TO {_APP_ROLE}")
    # SELECT + INSERT only — never UPDATE/DELETE (append-only at the grant layer too).
    for table in ("accounts", "transactions", "ledger_entries"):
        op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.{table} TO {_APP_ROLE}")

    # ---------------------------------------------------------------------- RLS
    for table in ("accounts", "transactions", "ledger_entries"):
        _enable_rls(table)


def downgrade() -> None:
    # Reverse dependency order. The `delta` schema is intentionally retained — it
    # houses the alembic_version table. Never touches tenant data.
    for table in ("accounts", "transactions", "ledger_entries"):
        op.execute(f"DROP POLICY IF EXISTS {table}_deny_delete ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_deny_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_deny_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_deny_delete ON {_SCHEMA}.{table}")

    op.execute(f"DROP TRIGGER IF EXISTS trg_le_balanced ON {_SCHEMA}.ledger_entries")
    op.execute(f"DROP TRIGGER IF EXISTS trg_le_in_txn_creation ON {_SCHEMA}.ledger_entries")

    # Revoke grants before dropping the tables they reference.
    for table in ("accounts", "transactions", "ledger_entries"):
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA {_SCHEMA} FROM {_APP_ROLE}")

    op.drop_index("ix_entry_txn", table_name="ledger_entries", schema=_SCHEMA)
    op.drop_index("ix_entry_tenant_account_ts", table_name="ledger_entries", schema=_SCHEMA)
    op.drop_table("ledger_entries", schema=_SCHEMA)

    op.drop_index("ux_txn_idempotency", table_name="transactions", schema=_SCHEMA)
    op.drop_index("ix_txn_tenant", table_name="transactions", schema=_SCHEMA)
    op.drop_table("transactions", schema=_SCHEMA)

    op.drop_index("ix_accounts_tenant", table_name="accounts", schema=_SCHEMA)
    op.drop_table("accounts", schema=_SCHEMA)

    op.execute(f"DROP FUNCTION IF EXISTS {_SCHEMA}.assert_txn_balanced()")
    op.execute(f"DROP FUNCTION IF EXISTS {_SCHEMA}.assert_entry_in_txn_creation()")
    op.execute(f"DROP FUNCTION IF EXISTS {_SCHEMA}.deny_ledger_modification()")

    # Drop delta_app only if it owns no objects (never destructive).
    op.execute(f"""
        DO $$
        DECLARE owned_count INT;
        BEGIN
            SELECT COUNT(*) INTO owned_count
            FROM pg_class c JOIN pg_roles r ON c.relowner = r.oid
            WHERE r.rolname = '{_APP_ROLE}';
            IF owned_count = 0 THEN
                DROP ROLE IF EXISTS {_APP_ROLE};
            ELSE
                RAISE NOTICE '{_APP_ROLE} owns % object(s); role not dropped.', owned_count;
            END IF;
        END
        $$;
        """)
