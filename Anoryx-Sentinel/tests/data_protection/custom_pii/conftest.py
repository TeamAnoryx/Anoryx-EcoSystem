"""Shared fixtures for tests/data_protection/custom_pii/ (F-028).

admin.py + loader.py use the persistence.database module-level engine
singletons (get_tenant_session). Dispose + null them before AND after each
test — mirrors tests/mcp_gateway/conftest.py exactly (same event-loop
isolation problem, same fix).
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
