"""Alembic migrations environment for Anoryx-AI-Orchestrator (O-003).

Ported from Anoryx-Sentinel/src/persistence/migrations/env.py. Uses the SYNC psycopg
driver for migrations. ORCH_DATABASE_URL (the privileged role) is loaded from .env via
python-dotenv; the asyncpg prefix is converted to psycopg here. No URL is ever logged.
"""

from __future__ import annotations

import os
import re
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

load_dotenv()


def _sync_database_url() -> str:
    """Return a psycopg-compatible sync URL derived from ORCH_DATABASE_URL."""
    raw = os.environ.get("ORCH_DATABASE_URL", "")
    if not raw:
        raise RuntimeError("ORCH_DATABASE_URL environment variable is not set.")
    url = re.sub(r"^postgresql\+asyncpg://", "postgresql+psycopg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+psycopg://", url)
    return url


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import models so their metadata is available (for compare_type / future autogenerate).
import orchestrator.persistence.models  # noqa: E402,F401  (registers all tables)
from orchestrator.persistence.models.base import Base  # noqa: E402

target_metadata = Base.metadata


def run_migrations_offline() -> None:
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
    url = _sync_database_url()
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
