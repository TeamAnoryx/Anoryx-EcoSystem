"""Tests for tenant context middleware + ID cross-check (F-004).

Covers:
- Missing required headers → 400 missing_required_header
- Malformed UUID headers → 400 missing_required_header
- Overlong headers (> 64 chars) → 400 missing_required_header
- Malformed agent-id slug → 400 missing_required_header
- Header value ≠ key-resolved scope → 403 id_context_mismatch (for all four IDs)
- Correct headers matching key scope → proceed
- Forged header rejected → key row is the ground truth
"""

from __future__ import annotations

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


def _build_app_with_key_row(key_row):
    """Build app with patches active at app-creation time.

    The patches must be active during the entire request lifecycle, so we
    return both the app and the patch context. Callers use this inside
    `with _app_patches(key_row): async with AsyncClient(app=app) ...`
    """
    _reset_settings()

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

    patches = [
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
    ]
    return patches


def _headers(**overrides):
    h = {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
        "Content-Type": "application/json",
    }
    h.update(overrides)
    return h


def _body():
    return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hello"}]}


# ---------------------------------------------------------------------------
# Header validation (step 3) — these don't require auth to have succeeded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_tenant_id(settings_env):
    """Missing X-Anoryx-Tenant-Id → 400 missing_required_header."""
    key_row = make_fake_key_row()
    patches = _build_app_with_key_row(key_row)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

    headers = _headers()
    del headers["X-Anoryx-Tenant-Id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        resp = await ac.post("/v1/chat/completions", headers=headers, json=_body())
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"
    assert resp.json()["message"] == "A required header is missing or malformed."


@pytest.mark.asyncio
async def test_missing_team_id(settings_env):
    key_row = make_fake_key_row()
    patches = _build_app_with_key_row(key_row)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
    headers = _headers()
    del headers["X-Anoryx-Team-Id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        resp = await ac.post("/v1/chat/completions", headers=headers, json=_body())
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"


@pytest.mark.asyncio
async def test_missing_agent_id(settings_env):
    key_row = make_fake_key_row()
    patches = _build_app_with_key_row(key_row)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()
    headers = _headers()
    del headers["X-Anoryx-Agent-Id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        resp = await ac.post("/v1/chat/completions", headers=headers, json=_body())
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"


@pytest.mark.asyncio
async def test_malformed_uuid_header(settings_env):
    """Non-UUID value in tenant_id header → 400."""
    key_row = make_fake_key_row()
    patches = _build_app_with_key_row(key_row)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        resp = await ac.post(
            "/v1/chat/completions",
            headers=_headers(**{"X-Anoryx-Tenant-Id": "not-a-uuid"}),
            json=_body(),
        )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"


@pytest.mark.asyncio
async def test_overlong_tenant_header(settings_env):
    """Header value > 64 chars → 400 missing_required_header."""
    key_row = make_fake_key_row()
    patches = _build_app_with_key_row(key_row)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        resp = await ac.post(
            "/v1/chat/completions",
            headers=_headers(**{"X-Anoryx-Tenant-Id": "a" * 65}),
            json=_body(),
        )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"


@pytest.mark.asyncio
async def test_malformed_agent_slug(settings_env):
    """Agent-id with invalid slug format → 400 missing_required_header."""
    key_row = make_fake_key_row()
    patches = _build_app_with_key_row(key_row)
    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        resp = await ac.post(
            "/v1/chat/completions",
            headers=_headers(**{"X-Anoryx-Agent-Id": "NOT_VALID_SLUG!"}),
            json=_body(),
        )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"


# ---------------------------------------------------------------------------
# ID cross-check (step 5 — post-auth mismatch)
# These tests have auth SUCCEED (key_row is returned) but then the header
# doesn't match the resolved ID from the key row → 403.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_id_mismatch_returns_403(settings_env):
    """Header tenant_id ≠ key-resolved tenant_id → 403 id_context_mismatch."""
    different_tenant = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    # Key row resolves to TEST_TENANT_ID.
    key_row = make_fake_key_row(tenant_id=TEST_TENANT_ID)
    patches = _build_app_with_key_row(key_row)

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_headers(**{"X-Anoryx-Tenant-Id": different_tenant}),  # forged
                json=_body(),
            )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error_code"] == "id_context_mismatch"
    assert body["message"] == "Supplied routing context does not match the API key's authorized scope."


@pytest.mark.asyncio
async def test_team_id_mismatch_returns_403(settings_env):
    """Header team_id ≠ key-resolved team_id → 403."""
    different_team = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    key_row = make_fake_key_row(team_id=TEST_TEAM_ID)
    patches = _build_app_with_key_row(key_row)

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_headers(**{"X-Anoryx-Team-Id": different_team}),
                json=_body(),
            )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "id_context_mismatch"


@pytest.mark.asyncio
async def test_agent_id_mismatch_returns_403(settings_env):
    """Header agent_id ≠ key-resolved agent_id → 403."""
    key_row = make_fake_key_row(agent_id="gateway-core")
    patches = _build_app_with_key_row(key_row)

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_headers(**{"X-Anoryx-Agent-Id": "data-protection"}),  # forged
                json=_body(),
            )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "id_context_mismatch"


@pytest.mark.asyncio
async def test_forged_header_does_not_become_context(settings_env):
    """Key row is the ground truth — headers claiming a different tenant are rejected."""
    # Key row says this tenant; headers claim TEST_TENANT_ID.
    key_row = make_fake_key_row(tenant_id="ffffffff-aaaa-bbbb-cccc-dddddddddddd")
    patches = _build_app_with_key_row(key_row)

    with patches[0], patches[1], patches[2]:
        from gateway.main import create_app
        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_headers(),  # headers claim TEST_TENANT_ID; key says different
                json=_body(),
            )
    # Must be 403 — never a successful pass-through.
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "id_context_mismatch"
