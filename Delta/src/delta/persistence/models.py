"""SQLAlchemy Core table definitions for the Delta ledger (D-003).

Core (not ORM) `Table` objects schema-qualified into ``delta``. The store and the
balance read primitives build statements against these; the authoritative DDL is the
Alembic migration (``versions/0001_ledger_schema.py``) — these definitions only
describe the columns the query layer references and are kept in lock-step with it.
"""

from __future__ import annotations

import sqlalchemy as sa

from . import DELTA_SCHEMA

metadata = sa.MetaData(schema=DELTA_SCHEMA)

accounts = sa.Table(
    "accounts",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("type", sa.String(16), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("name", sa.String(256), nullable=False),
)

transactions = sa.Table(
    "transactions",
    metadata,
    sa.Column("txn_id", sa.String(64), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    sa.Column("description", sa.String(512), nullable=False, server_default=""),
    sa.Column("reversal_of", sa.String(64), nullable=True),
    sa.Column("idempotency_key", sa.String(255), nullable=True),
)

ledger_entries = sa.Table(
    "ledger_entries",
    metadata,
    sa.Column("entry_id", sa.String(64), primary_key=True),
    sa.Column("txn_id", sa.String(64), nullable=False),
    sa.Column("tenant_id", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("direction", sa.String(8), nullable=False),
    sa.Column("amount_minor_units", sa.BigInteger, nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("team_id", sa.String(64), nullable=False),
    sa.Column("project_id", sa.String(64), nullable=False),
    sa.Column("agent_id", sa.String(64), nullable=False),
    sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
)
