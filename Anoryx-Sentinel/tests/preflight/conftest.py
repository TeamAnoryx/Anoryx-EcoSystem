"""Shared fixtures for tests/preflight/ (F-031).

The audit-chain check opens a privileged session via persistence.database's
engine singletons; dispose+null them before/after each test (same event-loop
isolation fix used across the suite).
"""

from __future__ import annotations

from typing import AsyncIterator

import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    async def _dispose() -> None:
        import persistence.database as _db

        for engine_attr, factory_attr in (
            ("_app_engine", "_app_session_factory"),
            ("_privileged_engine", "_privileged_session_factory"),
        ):
            engine = getattr(_db, engine_attr, None)
            if engine is not None:
                try:
                    await engine.dispose()
                except Exception:
                    pass
            setattr(_db, engine_attr, None)
            setattr(_db, factory_attr, None)

    await _dispose()
    yield
    await _dispose()
