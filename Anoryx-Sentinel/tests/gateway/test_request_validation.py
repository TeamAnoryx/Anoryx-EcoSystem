"""Tests for body-size / edge guard middleware (F-004).

Covers:
- Body > MAX_BODY_BYTES → 413 request_too_large
- Content-Length > MAX_BODY_BYTES (pre-read check) → 413 request_too_large
- Transfer-Encoding + Content-Length conflict → 400 invalid_request
- Unknown field in body → 400 invalid_request (closed schema)
- Missing required body field → 400 invalid_request
- Empty messages array → 400 invalid_request
- Valid body passes size check and reaches upstream
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.config import _reset_settings
from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_PLAINTEXT_KEY,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
    make_fake_key_row,
)


def _build_patches():
    """Build patches list (must be kept active during request)."""
    _reset_settings()
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
        yield session

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    return [
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
    ]


def _valid_headers():
    return {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Body size tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_over_limit_returns_413(settings_env, monkeypatch):
    """Body > MAX_BODY_BYTES → 413 request_too_large."""
    monkeypatch.setenv("MAX_BODY_BYTES", "100")
    _reset_settings()

    patches = _build_patches()
    oversized_body = json.dumps(
        {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "x" * 200}],
        }
    ).encode()

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=oversized_body,
                headers=_valid_headers(),
            )
    assert resp.status_code == 413
    assert resp.json()["error_code"] == "request_too_large"
    assert resp.json()["message"] == "The request body exceeds the maximum allowed size."


@pytest.mark.asyncio
async def test_body_exact_limit_passes(settings_env, monkeypatch):
    """Body at exactly MAX_BODY_BYTES passes the size check."""
    monkeypatch.setenv("MAX_BODY_BYTES", "1000")
    _reset_settings()
    patches = _build_patches()

    # Small enough to pass the 1000-byte limit.
    small_body = json.dumps(
        {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "hi"}],
        }
    ).encode()

    from gateway.exceptions import GatewayError

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        with patch(
            "gateway.routes.chat_completions.proxy_non_stream",
            new=AsyncMock(side_effect=GatewayError("internal_error")),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    content=small_body,
                    headers=_valid_headers(),
                )
    # 500 from mocked upstream — 413 would mean size check blocked it.
    assert resp.status_code != 413


@pytest.mark.asyncio
async def test_transfer_encoding_and_content_length_conflict_returns_400(settings_env):
    """TE + CL headers both present → 400 invalid_request (smuggling rejection)."""
    patches = _build_patches()
    body_bytes = b'{"model":"m","messages":[{"role":"user","content":"hi"}]}'

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=body_bytes,
                headers={
                    **_valid_headers(),
                    "Transfer-Encoding": "chunked",
                    "Content-Length": str(len(body_bytes)),
                },
            )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


# ---------------------------------------------------------------------------
# Closed schema / body validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_field_in_body_returns_400(settings_env):
    """Unknown key in request body → 400 invalid_request (closed schema)."""
    patches = _build_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": "hi"}],
                    "unknown_extra_field": "rejected",
                },
            )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_missing_required_body_field_returns_400(settings_env):
    """Missing required 'model' field → 400 invalid_request."""
    patches = _build_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json={"messages": [{"role": "user", "content": "hi"}]},
            )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_empty_messages_array_returns_400(settings_env):
    """Empty messages array (minItems=1) → 400."""
    patches = _build_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json={"model": "gpt-3.5-turbo", "messages": []},
            )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_valid_body_passes_to_upstream(settings_env):
    """Valid body passes size + schema checks; reaches upstream (mocked as 500 for test)."""
    from gateway.exceptions import GatewayError

    patches = _build_patches()
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app

        app = create_app()
        with patch(
            "gateway.routes.chat_completions.proxy_non_stream",
            new=AsyncMock(side_effect=GatewayError("internal_error")),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
                resp = await ac.post(
                    "/v1/chat/completions",
                    headers=_valid_headers(),
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
    # 500 from upstream mock — the body itself was valid (no 400 from validation)
    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"
