"""Shared pytest fixtures for gateway tests (F-004).

Uses httpx.AsyncClient with ASGITransport to test the FastAPI app without
starting a real server. DB persistence calls are mocked at the repository layer.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from gateway.config import GatewaySettings, _reset_settings
from gateway.middleware.rate_limit import reset_state_for_testing

# ---------------------------------------------------------------------------
# Canonical test IDs (server-resolved values — what the key row returns)
# ---------------------------------------------------------------------------
TEST_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEST_TEAM_ID = "11111111-2222-3333-4444-555555555555"
TEST_PROJECT_ID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
TEST_AGENT_ID = "gateway-core"
TEST_KEY_ID = str(uuid.uuid4())
TEST_PLAINTEXT_KEY = "sk-sentinel-test-key-abc123"
TEST_MODEL = "gpt-3.5-turbo"


def make_fake_key_row(
    tenant_id: str = TEST_TENANT_ID,
    team_id: str = TEST_TEAM_ID,
    project_id: str = TEST_PROJECT_ID,
    agent_id: str = TEST_AGENT_ID,
    key_id: str = TEST_KEY_ID,
    is_active: bool = True,
):
    """Build a MagicMock mimicking a VirtualApiKey ORM row."""
    row = MagicMock()
    row.tenant_id = tenant_id
    row.team_id = team_id
    row.project_id = project_id
    row.agent_id = agent_id
    row.key_id = key_id
    row.is_active = is_active
    return row


# Keep old name for backward compatibility within this module.
_make_fake_key_row = make_fake_key_row


def make_privileged_session_cm(repo_mock):
    """Return a patched get_privileged_session context manager factory."""

    @asynccontextmanager
    async def _cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        with patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=repo_mock):
            yield session

    return _cm


def make_audit_session_cm(audit_repo_mock):
    """Return a patched get_privileged_session for audit calls."""

    @asynccontextmanager
    async def _cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        with patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock):
            yield session

    return _cm


def make_privileged_session_cm_for_both(auth_repo_mock, audit_repo_mock):
    """Return a get_privileged_session CM that serves both auth and audit calls.

    Uses call counting to decide which repo to serve. Auth calls always come
    before audit calls within a single request.
    """
    call_count = [0]

    @asynccontextmanager
    async def _cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        call_count[0] += 1
        if call_count[0] == 1:
            with patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo_mock):
                yield session
        else:
            with patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock):
                yield session

    return _cm


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """Clear in-process rate-limit state before every test."""
    reset_state_for_testing()
    yield
    reset_state_for_testing()


@pytest.fixture(autouse=True)
def _ensure_gateway_env(monkeypatch):
    """Ensure required gateway env vars are always set for gateway tests.

    Autouse within tests/gateway/ so every test has the minimum required env.
    This prevents GatewaySettings from failing when the full suite runs and
    DATABASE_URL is set (from persistence tests) but UPSTREAM_BASE_URL is not.
    """
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://fake-upstream")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/db")
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+asyncpg://fake/appdb")
    monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-secret-for-hmac")
    # Override any real .env CORS_ALLOWED_ORIGINS that may be a non-JSON string.
    # pydantic-settings requires list[str] fields to be JSON-encoded in env vars.
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    # Pin numeric settings to known defaults so tests that assert exact values
    # (e.g. limit == 600) are deterministic regardless of real .env content.
    monkeypatch.setenv("RATE_LIMIT_RPM", "600")
    monkeypatch.setenv("RATE_LIMIT_BURST", "60")
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "20")
    _reset_settings()
    yield
    _reset_settings()


@pytest.fixture()
def settings_env(_ensure_gateway_env):
    """Alias for _ensure_gateway_env. Kept for explicit test declarations."""
    yield


@pytest.fixture()
def fake_key_row():
    return make_fake_key_row()


def build_app_with_auth(key_row=None, audit_append=None):
    """Build the gateway app with mocked auth and audit.

    key_row: VirtualApiKey mock row. Defaults to a standard test row.
    audit_append: AsyncMock for AuditLogRepository.append. Defaults to no-op.

    NOTE: This helper patches emit_terminal_record at the ROUTE level, which
    suppresses double-audit from TerminalAuditMiddleware. Use
    build_app_with_real_audit() for regression tests that must prove audit
    fires for middleware-stage rejections.
    """
    _reset_settings()
    if key_row is None:
        key_row = make_fake_key_row()

    # --- Auth repo mock ---
    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    # --- Audit repo mock ---
    audit_repo = MagicMock()
    audit_repo.append = audit_append or AsyncMock(return_value=MagicMock())

    # We need get_privileged_session to work for BOTH auth lookups and audit appends.
    # Both are separate calls; we patch the function to return a new CM each time.
    call_count = [0]

    @asynccontextmanager
    async def _privileged_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        call_count[0] += 1
        # The mock repos are installed via direct patches on the route handler
        # and auth middleware, so we just yield a dummy session here.
        yield session

    import gateway.upstream.openai_proxy as proxy_mod
    proxy_mod._http_client = None

    with (
        patch("gateway.middleware.auth.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.middleware.audit.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
    ):
        from gateway.main import create_app
        app = create_app()

    return app


def build_app_with_real_audit(key_row=None, audit_repo_mock=None):
    """Build the gateway app with mocked auth but REAL audit path.

    Unlike build_app_with_auth(), this does NOT patch out emit_terminal_record
    at the route level. This allows the TerminalAuditMiddleware to call the
    real emit_terminal_record(), proving the audit bypass is dead.

    audit_repo_mock: a MagicMock with an .append AsyncMock; if None, a default
    no-op mock is used. Callers inspect audit_repo_mock.append.call_count to
    assert audit fires for middleware rejections.

    Returns (app, audit_repo_mock) so callers can assert on the repo mock.
    """
    _reset_settings()
    if key_row is None:
        key_row = make_fake_key_row()

    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    if audit_repo_mock is None:
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = AsyncMock(return_value=MagicMock())

    @asynccontextmanager
    async def _privileged_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        # Both auth and audit share the same session mock; they're patched separately.
        yield session

    import gateway.upstream.openai_proxy as proxy_mod
    proxy_mod._http_client = None

    with (
        patch("gateway.middleware.auth.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.middleware.audit.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock),
        # NOTE: Do NOT patch gateway.routes.chat_completions.emit_terminal_record here.
        # The real function is called so TerminalAuditMiddleware invocations
        # go through to the mocked AuditLogRepository.
    ):
        from gateway.main import create_app
        app = create_app()

    return app, audit_repo_mock


@pytest.fixture()
def standard_headers():
    """Standard valid Sentinel routing headers matching TEST_* constants."""
    return {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
        "Content-Type": "application/json",
    }
