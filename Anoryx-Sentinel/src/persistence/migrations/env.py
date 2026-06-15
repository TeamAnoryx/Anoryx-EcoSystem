"""Alembic migrations environment for Anoryx-Sentinel (F-003).

Uses the SYNC psycopg driver for migrations (psycopg, not asyncpg).
DATABASE_URL is loaded from .env via python-dotenv; the asyncpg URL prefix
is converted to postgresql+psycopg:// here. No URL is ever logged or printed.
"""
from __future__ import annotations

import os
import re
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

# ---------------------------------------------------------------------------
# Load .env (sentinel at repo root, or wherever python-dotenv finds it).
# Never log or print the resulting DATABASE_URL.
# ---------------------------------------------------------------------------
load_dotenv()


def _sync_database_url() -> str:
    """Return a psycopg-compatible sync URL derived from DATABASE_URL.

    Converts asyncpg-style URLs (postgresql+asyncpg:// or postgresql://)
    to postgresql+psycopg:// for migration use.
    Raises RuntimeError if DATABASE_URL is absent.
    """
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL environment variable is not set.")

    # Replace known asyncpg/default prefixes with psycopg sync driver.
    url = re.sub(r"^postgresql\+asyncpg://", "postgresql+psycopg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+psycopg://", url)
    return url


# ---------------------------------------------------------------------------
# Alembic config object (provides access to .ini values).
# ---------------------------------------------------------------------------
config = context.config

# Interpret logging config in alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all models so their metadata is available to Alembic autogenerate.
# We import Base here; individual model files register their tables on it.
from persistence.models.base import Base  # noqa: E402

target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Migration runners
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (SQL script output)."""
    url = _sync_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    url = _sync_database_url()
    # Override the sqlalchemy.url from the ini file with our runtime-resolved URL.
    config.set_main_option("sqlalchemy.url", url)

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
