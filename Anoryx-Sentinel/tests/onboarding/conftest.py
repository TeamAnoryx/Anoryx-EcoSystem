"""Shared fixtures for tests/onboarding/ (F-025).

sandbox.py uses the persistence.database module-level engine singletons
(get_privileged_session / get_tenant_session) — the same production code path
admin/tenants.py and admin/keys.py use. pytest-asyncio gives each test
function its own event loop by default, so a singleton engine created in one
test's loop breaks a later test that reuses it ("Future attached to a
different loop"). Dispose + null the singletons before AND after each test —
mirrors tests/gateway/conftest.py's _reset_db_engine_caches exactly.
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
