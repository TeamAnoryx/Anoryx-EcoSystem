"""Alembic migrations environment for Rendly identity persistence (R-004).

Uses the SYNC psycopg driver for migrations (psycopg is also the app-runtime driver —
Rendly is sync end-to-end). DATABASE_URL is the privileged owner role (BYPASSRLS):
migrations must run as the owner, never as ``rendly_app``. No URL is ever logged.

Rendly identity lives in its OWN ``rendly`` schema (Fork A). The alembic_version
bookkeeping table is pinned into that schema (``version_table_schema="rendly"``) so
Rendly's migration history never collides with another product's ``public.alembic_version``
when they share a Postgres instance. The schema is created here, before any migration
runs, so the version table has a home. Migrations are hand-written (no autogenerate), so
``target_metadata`` is None.
"""

from __future__ import annotations

import os
import re
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool, text

# Load .env (Rendly root or monorepo root, wherever python-dotenv finds it). The
# resulting DATABASE_URL is never logged or printed.
load_dotenv()

_SCHEMA = "rendly"


def _sync_database_url() -> str:
    """Return a psycopg-compatible sync URL derived from DATABASE_URL (fail loud if unset)."""
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. Rendly migrations require the "
            "privileged owner role connection (see Rendly/docker-compose.yml)."
        )
    url = re.sub(r"^postgresql\+asyncpg://", "postgresql+psycopg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+psycopg://", url)
    return url


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Hand-written migrations only (no autogenerate): the identity DDL, RLS, role, and grants
# are authored explicitly, so there is no model metadata to diff against.
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
        compare_type=True,
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
        # Idempotent; migration 0001 also CREATE SCHEMA IF NOT EXISTS (harmless). _SCHEMA
        # is a fixed module constant ("rendly"), never user input — no injection surface,
        # and DDL cannot be parameterized anyway.
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))  # nosemgrep
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=_SCHEMA,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
