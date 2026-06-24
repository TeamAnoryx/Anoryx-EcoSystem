"""Shared fixtures for orchestration tests (F-005).

Provides:
  - Synthetic tenant context (server-resolved IDs, never real PII).
  - Mock HookContext with recording emit().
  - Mock HookRegistry stubs (pass-through, recording, raising).
  - Env var setup for OrchestrationSettings.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from gateway.context import TenantContext
from orchestration.config import _reset_orchestration_settings


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    """Dispose + null persistence.database engine singletons before AND after each
    test, so a fake-host APP_DATABASE_URL engine built here (these tests monkeypatch
    it) never leaks into a later package's real connect, and a leaked engine from a
    prior test is never reused here (f-019)."""

    async def _dispose() -> None:
        import persistence.database as _db

        for _engine_attr, _factory_attr in (
            ("_app_engine", "_app_session_factory"),
            ("_privileged_engine", "_privileged_session_factory"),
        ):
            _engine = getattr(_db, _engine_attr, None)
            if _engine is not None:
                try:
                    await _engine.dispose()
                except Exception:
                    pass
            setattr(_db, _engine_attr, None)
            setattr(_db, _factory_attr, None)

    await _dispose()
    yield
    await _dispose()


# ---------------------------------------------------------------------------
# Synthetic test IDs (no real PII — purely synthetic UUIDs).
# ---------------------------------------------------------------------------
TEST_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
TEST_TEAM_ID = "11111111-2222-3333-4444-000000000002"
TEST_PROJECT_ID = "66666666-7777-8888-9999-000000000003"
TEST_AGENT_ID = "test-agent"
TEST_KEY_ID = str(uuid.uuid4())
TEST_REQUEST_ID = "req-00000000000000000000000000000001"


@pytest.fixture()
def tenant_context() -> TenantContext:
    """Synthetic server-resolved TenantContext for tests."""
    return TenantContext(
        tenant_id=TEST_TENANT_ID,
        team_id=TEST_TEAM_ID,
        project_id=TEST_PROJECT_ID,
        agent_id=TEST_AGENT_ID,
        virtual_key_id=TEST_KEY_ID,
    )


@pytest.fixture()
def orchestration_env(monkeypatch):
    """Set required env vars for OrchestrationSettings in tests."""
    monkeypatch.setenv("PII_DETECTION_ENABLED", "true")
    monkeypatch.setenv("PII_ACTION", "mask")
    monkeypatch.setenv("PII_CONFIDENCE_THRESHOLD", "0.85")
    monkeypatch.setenv("MAX_PII_INSPECT_CHARS", "50000")
    monkeypatch.setenv("INJECTION_DETECTION_ENABLED", "true")
    monkeypatch.setenv("INJECTION_SCORE_THRESHOLD", "0.75")
    monkeypatch.setenv("SECRET_DETECTION_ENABLED", "true")
    monkeypatch.setenv("SECRET_REDACT_CHARACTER", "*")
    monkeypatch.setenv("ENTROPY_THRESHOLD", "4.5")
    monkeypatch.setenv("MIN_TOKEN_LENGTH_FOR_ENTROPY", "20")
    monkeypatch.setenv("EVENTS_PER_DETECTOR_CAP", "10")
    monkeypatch.setenv("STREAM_INSPECT_BUFFER_BYTES", "8192")
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    _reset_orchestration_settings()
    yield
    _reset_orchestration_settings()


@pytest.fixture()
def mock_emit():
    """An AsyncMock that records calls to HookContext.emit()."""
    return AsyncMock(return_value=True)


@pytest.fixture()
def mock_hook_context(tenant_context, mock_emit, monkeypatch):
    """A MagicMock HookContext with a recording emit()."""
    ctx = MagicMock()
    ctx.tenant_context = tenant_context
    ctx.request_id = TEST_REQUEST_ID
    ctx.original_user_content = ""
    ctx.phase = "pre_request"
    ctx._events_per_detector_cap = 10
    ctx._event_budget = {}
    ctx.emit = mock_emit
    ctx.budget_exhausted = MagicMock(return_value=False)
    return ctx


def make_mock_privileged_session(audit_repo_mock=None):
    """Return a patched get_privileged_session context manager for orchestration."""
    if audit_repo_mock is None:
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = AsyncMock(return_value=MagicMock())

    @asynccontextmanager
    async def _cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    return _cm, audit_repo_mock
