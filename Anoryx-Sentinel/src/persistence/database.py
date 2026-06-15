"""Database engine and session factory for Anoryx-Sentinel (F-003).

F-003 ships a single session helper: get_async_session().

Runtime tenant isolation (sentinel_app role, GUC-based tenant scoping,
BYPASSRLS session separation) is NOT implemented here and is deferred to F-003b,
which MUST merge before F-004.  See ADR-0004 for the full scope statement.

DATABASE_URL is loaded from the environment (via python-dotenv in fleet processes).
The URL is NEVER logged or printed.
"""
from __future__ import annotations

import os
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _async_database_url() -> str:
    """Return an asyncpg-compatible async URL from DATABASE_URL.

    Converts postgresql:// and postgresql+psycopg:// to postgresql+asyncpg://.
    Raises RuntimeError if DATABASE_URL is absent.
    """
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


# ---------------------------------------------------------------------------
# Engine singletons (lazy, one per process)
# ---------------------------------------------------------------------------

_engine: object | None = None
_session_factory: async_sessionmaker | None = None


def _get_engine():  # type: ignore[return]
    global _engine
    if _engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        url = _async_database_url()
        _engine = _cae(
            url,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            echo=False,
        )
    return _engine


def _get_session_factory() -> async_sessionmaker:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


# ---------------------------------------------------------------------------
# Public session helper
# ---------------------------------------------------------------------------

@asynccontextmanager
async def get_async_session() -> AsyncIterator[AsyncSession]:
    """Async session context manager.

    Yields an AsyncSession from the module-level session factory.
    The session does NOT set any tenant GUC and does NOT perform role
    switching — both are deferred to F-003b.

    Usage:
        async with get_async_session() as session:
            async with session.begin():
                ...
    """
    factory = _get_session_factory()
    async with factory() as session:
        yield session


def create_engine_from_env() -> object:
    """Create and return a SQLAlchemy async engine from DATABASE_URL.

    Exposed for use by test fixtures that build their own engine.
    """
    from sqlalchemy.ext.asyncio import create_async_engine as _cae

    url = _async_database_url()
    return _cae(
        url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        echo=False,
    )
