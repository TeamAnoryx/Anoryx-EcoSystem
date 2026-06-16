"""Tests for gateway authentication middleware (F-004).

Covers:
- Missing Authorization header → 401 invalid_api_key
- Malformed (non-Bearer) Authorization → 401 invalid_api_key
- Empty Bearer token → 401 invalid_api_key
- VirtualApiKeyAuthError (revoked/expired/inactive) → 401 invalid_api_key
- DB error during lookup → 500 internal_error
- GET /health exempt from auth → 200
- GET /ready exempt from auth (no 401)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.config import _reset_settings
from gateway.middleware.rate_limit import reset_state_for_testing
from persistence.repositories.virtual_api_key_repository import VirtualApiKeyAuthError

from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_PLAINTEXT_KEY,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
    make_fake_key_row,
)


def _valid_headers(**overrides):
    h = {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Content-Type": "application/json",
    }
    h.update(overrides)
    return h


def _body():
    return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]}


def _build_app_patches(lookup_return=None, lookup_side_effect=None):
    """Return (patches, app) with patches kept active.

    Caller must use patches[0], patches[1], patches[2] as context managers
    during the entire request lifecycle — not just during app creation.
    """
    _reset_settings()

    key_row = lookup_return or make_fake_key_row()
    auth_repo = MagicMock()
    if lookup_side_effect:
        auth_repo.lookup_by_plaintext = AsyncMock(side_effect=lookup_side_effect)
    else:
        auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    import gateway.upstream.openai_proxy as proxy_mod
    proxy_mod._http_client = None

    return [
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
    ]


def _build_app(lookup_return=None, lookup_side_effect=None):
    """Build app (patches applied only during app creation — use for simple tests)."""
    patches = _build_app_patches(lookup_return, lookup_side_effect)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
    return app


@pytest.mark.asyncio
async def test_missing_authorization_header(settings_env):
    """Missing Authorization header → 401 invalid_api_key."""
    patches = _build_app_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post("/v1/chat/completions", headers=_valid_headers(), json=_body())
    assert resp.status_code == 401
    body = resp.json()
    assert body["error_code"] == "invalid_api_key"
    assert body["message"] == "Virtual API key is missing, revoked, or invalid."
    assert "request_id" in body
    assert "x-request-id" in resp.headers


@pytest.mark.asyncio
async def test_non_bearer_authorization(settings_env):
    """Authorization header without 'Bearer ' prefix → 401."""
    patches = _build_app_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(Authorization="Basic abc123"),
                json=_body(),
            )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_api_key"


@pytest.mark.asyncio
async def test_empty_bearer_token(settings_env):
    """'Bearer ' with no token → 401."""
    patches = _build_app_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(Authorization="Bearer "),
                json=_body(),
            )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_api_key"


@pytest.mark.asyncio
async def test_invalid_key_auth_error(settings_env):
    """VirtualApiKeyAuthError → 401 invalid_api_key."""
    _reset_settings()

    auth_repo_bad = MagicMock()
    auth_repo_bad.lookup_by_plaintext = AsyncMock(side_effect=VirtualApiKeyAuthError("revoked"))

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    import gateway.upstream.openai_proxy as proxy_mod
    proxy_mod._http_client = None

    p1 = patch("gateway.middleware.auth.get_privileged_session", _priv_cm)
    p2 = patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo_bad)
    p3 = patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock())

    with p1, p2, p3:
        from gateway.main import create_app
        app2 = create_app()

        async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(Authorization=f"Bearer {TEST_PLAINTEXT_KEY}"),
                json=_body(),
            )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_api_key"


@pytest.mark.asyncio
async def test_db_error_during_auth_returns_500(settings_env):
    """Unexpected DB error during lookup → 500 internal_error."""
    _reset_settings()

    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(side_effect=RuntimeError("DB down"))

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    import gateway.upstream.openai_proxy as proxy_mod
    proxy_mod._http_client = None

    p1 = patch("gateway.middleware.auth.get_privileged_session", _priv_cm)
    p2 = patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo)
    p3 = patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock())

    with p1, p2, p3:
        from gateway.main import create_app
        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(Authorization=f"Bearer {TEST_PLAINTEXT_KEY}"),
                json=_body(),
            )
    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"


@pytest.mark.asyncio
async def test_health_exempt_from_auth(settings_env):
    """GET /health does not require Authorization header."""
    patches = _build_app_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ready_exempt_from_auth(settings_env):
    """GET /ready does not require auth (DB check mocked)."""
    _reset_settings()
    import gateway.upstream.openai_proxy as proxy_mod
    proxy_mod._http_client = None
    key_row = make_fake_key_row()
    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        session.execute = AsyncMock(return_value=MagicMock())
        yield session

    p1 = patch("gateway.middleware.auth.get_privileged_session", _priv_cm)
    p2 = patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo)
    p3 = patch("gateway.routes.health.get_privileged_session", _priv_cm)
    p4 = patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock())

    with p1, p2, p3, p4:
        from gateway.main import create_app
        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.get("/ready")
    # Not 401 (exempt from auth).
    assert resp.status_code != 401
    assert resp.status_code in (200, 503)
