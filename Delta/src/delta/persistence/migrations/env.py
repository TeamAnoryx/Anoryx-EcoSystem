"""Alembic migrations environment for the Delta ledger (D-003).

Uses the SYNC psycopg driver for migrations (asyncpg is the app-runtime driver).
DATABASE_URL is the privileged owner role (BYPASSRLS) — migrations must run as the
owner, never as ``delta_app``. No URL is ever logged or printed.

The Delta ledger lives in its own ``delta`` schema (Fork 4). The alembic_version
bookkeeping table is pinned into that schema so Delta's migration history never
collides with another product's ``public.alembic_version`` when they share a
Postgres instance. The schema is created here, before any migration runs, so the
version table has a home.
"""

from __future__ import annotations

import os
import re
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool, text

# Load .env (Delta root or monorepo root, wherever python-dotenv finds it).
# Never log or print the resulting DATABASE_URL.
load_dotenv()

_SCHEMA = "delta"


def _sync_database_url() -> str:
    """Return a psycopg-compatible sync URL derived from DATABASE_URL.

    Converts asyncpg-style URLs (postgresql+asyncpg:// or postgresql://) to
    postgresql+psycopg:// for migration use. Raises RuntimeError if DATABASE_URL
    is absent (fail loud — never silently migrate against a default).
    """
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. Delta migrations require "
            "the privileged owner role connection (see Delta/.env.example)."
        )
    url = re.sub(r"^postgresql\+asyncpg://", "postgresql+psycopg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+psycopg://", url)
    return url


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Hand-written migrations only (no autogenerate) — the ledger DDL, RLS, role, and
# triggers are authored explicitly, so there is no model metadata to diff against.
target_metadata = None


def run_migrations_offline() -> None:
    """Emit migration SQL without a live connection (script output only)."""
    url = _sync_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table_schema=_SCHEMA,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection (the round-trip path)."""
    url = _sync_database_url()
    config.set_main_option("sqlalchemy.url", url)

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # Ensure the schema exists before Alembic creates its version table there.
        # Idempotent; migration 0001 also CREATE SCHEMA IF NOT EXISTS (harmless).
        # _SCHEMA is a fixed module constant ("delta"), never user input — no
        # injection surface, and DDL cannot be parameterized anyway.
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))  # nosemgrep
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=_SCHEMA,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
