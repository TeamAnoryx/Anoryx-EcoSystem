"""End-to-end tests for POST /v1/chat/completions (F-004).

CONTRACT TESTS (must always pass):
- error_code→message pairing is 1:1 verbatim from contracts/openapi.yaml
- ChatCompletionResponse shape has all openapi required fields
- Usage event conforms to contracts/events.schema.json

Full pipeline tests:
- Happy path: valid key + headers + body → 200 + correct shape + response headers
- Audit emitted on success and on invalid_request failures
- 500 on upstream failure (never 502/504 per contract)
- 429 + Retry-After on rate limit exceeded
- 413 on oversized body
- request_id echoed in both X-Request-Id header and body on all errors
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.config import _reset_settings
from gateway.exceptions import ERROR_TABLE
from policy.enforcement import BudgetOk, ModelAllow
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
        "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
        "Content-Type": "application/json",
    }
    h.update(overrides)
    return h


def _valid_body():
    return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}


def _make_upstream_resp(status_code=200, body=None):
    if body is None:
        body = {
            "id": "chatcmpl-e2e",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-3.5-turbo",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hi!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json = MagicMock(return_value=body)
    return mock_resp


def _build_patches(key_row=None, audit_mock=None):
    """Return patches list and the audit_mock. Keep patches active during requests."""
    _reset_settings()
    if key_row is None:
        key_row = make_fake_key_row()

    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    _audit = audit_mock or AsyncMock()

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    # F-006: the router resolves the tenant routing policy on a tenant session
    # and emits routing_decision events on the privileged session. Stub both so
    # the OpenAI happy/failure paths exercise the router without a live DB. The
    # default policy (no row) routes to OpenAI exactly as before.
    from persistence.repositories.tenant_routing_policy_repository import default_policy

    @asynccontextmanager
    async def _tenant_cm(tenant_id):
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    async def _fake_get_for_tenant(self, tenant_id, caller_tenant_id):
        return default_policy(tenant_id)

    # F-008 (ADR-0009 §6): stub the model/budget gate to "allow, no budgets" so the
    # F-004/F-006 pipeline tests exercise the route without a live policy DB. The
    # gate's own behavior is covered in tests/policy/.
    async def _allow_enforce(tenant_context, body):
        return ModelAllow(None), BudgetOk(), []

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    patches = [
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=_audit),
        # Router DB touchpoints (F-006).
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
        patch("persistence.database.get_tenant_session", _tenant_cm),
        patch(
            "persistence.repositories.tenant_routing_policy_repository."
            "TenantRoutingPolicyRepository.get_for_tenant",
            new=_fake_get_for_tenant,
        ),
        patch("gateway.router.selection._enforce_policies_pre_request", new=_allow_enforce),
    ]
    return patches, _audit


# ---------------------------------------------------------------------------
# Happy path E2E
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_happy_path_non_stream(settings_env):
    """Full happy path: auth + headers + body → 200 + correct shape + response headers."""
    upstream_resp = _make_upstream_resp()
    patches, _ = _build_patches()

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=upstream_resp)

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        from gateway.main import create_app

        app = create_app()
        with patch("gateway.upstream.openai_proxy._http_client", mock_client):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
                resp = await ac.post(
                    "/v1/chat/completions", headers=_valid_headers(), json=_valid_body()
                )

    assert resp.status_code == 200
    body = resp.json()
    assert body["object"] == "chat.completion"
    assert "id" in body
    assert "choices" in body
    assert "model" in body
    assert "created" in body

    # Required response headers per contract.
    assert "x-request-id" in resp.headers
    assert "x-ratelimit-limit" in resp.headers
    assert "x-ratelimit-remaining" in resp.headers
    assert "x-ratelimit-reset" in resp.headers


@pytest.mark.asyncio
async def test_e2e_audit_emitted_on_success(settings_env):
    """emit_terminal_record is called on successful 200."""
    upstream_resp = _make_upstream_resp()
    audit_mock = AsyncMock()
    patches, audit_fn = _build_patches(audit_mock=audit_mock)

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=upstream_resp)

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        from gateway.main import create_app

        app = create_app()
        with patch("gateway.upstream.openai_proxy._http_client", mock_client):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
                await ac.post("/v1/chat/completions", headers=_valid_headers(), json=_valid_body())

    audit_mock.assert_awaited_once()
    call_kwargs = audit_mock.call_args.kwargs
    assert call_kwargs["tenant_context"].tenant_id == TEST_TENANT_ID
    assert call_kwargs["model"] == "gpt-3.5-turbo"
    assert "request_id" in call_kwargs


@pytest.mark.asyncio
async def test_e2e_audit_emitted_on_invalid_request(settings_env):
    """emit_terminal_record is called even when body validation fails (400)."""
    audit_mock = AsyncMock()
    patches, _ = _build_patches(audit_mock=audit_mock)

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json={"messages": [{"role": "user", "content": "hi"}]},  # missing model
            )

    assert resp.status_code == 400
    audit_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_e2e_upstream_failure_returns_500_not_502(settings_env):
    """Upstream connect error → 500 on wire (never 502/504 per contract)."""
    import httpx

    patches, _ = _build_patches()

    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        from gateway.main import create_app

        app = create_app()
        with patch("gateway.upstream.openai_proxy._http_client", mock_client):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
                resp = await ac.post(
                    "/v1/chat/completions", headers=_valid_headers(), json=_valid_body()
                )

    assert resp.status_code == 500
    body = resp.json()
    assert body["error_code"] == "internal_error"
    assert body["message"] == "An internal error occurred. The request was not processed."
    assert "x-request-id" in resp.headers
    # request_id in both header and body.
    assert body["request_id"] == resp.headers["x-request-id"]


@pytest.mark.asyncio
async def test_e2e_request_id_echoed_in_header_and_body(settings_env):
    """request_id in X-Request-Id header AND in error body on all errors."""
    patches, _ = _build_patches()

    # Send bad credentials.
    bad_auth_repo = MagicMock()
    from persistence.repositories.virtual_api_key_repository import VirtualApiKeyAuthError

    bad_auth_repo.lookup_by_plaintext = AsyncMock(side_effect=VirtualApiKeyAuthError("bad"))

    with (
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=bad_auth_repo),
        patches[0],
        patches[2],
    ):
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json=_valid_body(),
            )

    assert resp.status_code == 401
    body = resp.json()
    assert "request_id" in body
    assert "x-request-id" in resp.headers
    assert body["request_id"] == resp.headers["x-request-id"]


@pytest.mark.asyncio
async def test_e2e_rate_limit_returns_429_with_retry_after(settings_env, monkeypatch):
    """Rate limit exceeded → 429 + Retry-After header."""
    monkeypatch.setenv("RATE_LIMIT_RPM", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "100")
    _reset_settings()

    upstream_resp = _make_upstream_resp()
    audit_mock = AsyncMock()
    patches, _ = _build_patches(audit_mock=audit_mock)

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=upstream_resp)

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        from gateway.main import create_app

        app = create_app()
        with patch("gateway.upstream.openai_proxy._http_client", mock_client):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
                r1 = await ac.post(
                    "/v1/chat/completions", headers=_valid_headers(), json=_valid_body()
                )
                r2 = await ac.post(
                    "/v1/chat/completions", headers=_valid_headers(), json=_valid_body()
                )

    assert r1.status_code == 200
    assert r2.status_code == 429
    assert r2.json()["error_code"] == "rate_limit_exceeded"
    assert "retry-after" in r2.headers


@pytest.mark.asyncio
async def test_e2e_413_on_oversized_body(settings_env, monkeypatch):
    """Body > MAX_BODY_BYTES → 413."""
    monkeypatch.setenv("MAX_BODY_BYTES", "50")
    _reset_settings()
    patches, _ = _build_patches()

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=b"x" * 200,
                headers=_valid_headers(),
            )
    assert resp.status_code == 413
    assert resp.json()["error_code"] == "request_too_large"


# ---------------------------------------------------------------------------
# CONTRACT TEST: error_code → message → status (verbatim, pinned)
# ---------------------------------------------------------------------------


def test_error_table_code_message_pairing():
    """MUST PASS: each error_code maps to exactly one verbatim contract message."""
    verbatim_mapping = {
        "missing_required_header": "A required header is missing or malformed.",
        "invalid_request": "The request body is invalid or violates a field constraint.",
        "request_too_large": "The request body exceeds the maximum allowed size.",
        "invalid_api_key": "Virtual API key is missing, revoked, or invalid.",
        "id_context_mismatch": "Supplied routing context does not match the API key's authorized scope.",  # noqa: E501
        "policy_blocked": "Request blocked by policy for this tenant/team/project/agent context.",
        "rate_limit_exceeded": "Rate limit exceeded. Retry after the window resets.",
        "not_found": "The requested resource was not found.",
        "internal_error": "An internal error occurred. The request was not processed.",
    }
    for code, expected_message in verbatim_mapping.items():
        actual_message, _ = ERROR_TABLE[code]
        assert actual_message == expected_message, (
            f"Message for {code!r} diverged from contract.\n"
            f"  Expected: {expected_message!r}\n"
            f"  Actual:   {actual_message!r}"
        )
    assert set(ERROR_TABLE.keys()) == set(
        verbatim_mapping.keys()
    ), "ERROR_TABLE keys differ from contract error_code enum"


# ---------------------------------------------------------------------------
# CONTRACT TEST: ChatCompletionResponse shape matches openapi schema
# ---------------------------------------------------------------------------


def test_chat_completion_response_shape():
    """ChatCompletionResponse has all fields required by contracts/openapi.yaml."""
    from gateway.models import ChatCompletionChoice, ChatCompletionResponse, ChatMessage, UsageBlock

    response = ChatCompletionResponse(
        id="chatcmpl-test",
        object="chat.completion",
        created=1700000000,
        model="gpt-3.5-turbo",
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content="Hello!"),
                finish_reason="stop",
            )
        ],
        usage=UsageBlock(prompt_tokens=5, completion_tokens=3, total_tokens=8),
    )
    data = response.model_dump()

    for field in ["id", "object", "created", "model", "choices"]:
        assert field in data, f"Required field {field!r} missing from ChatCompletionResponse"

    assert data["object"] == "chat.completion"
    choice = data["choices"][0]
    assert "index" in choice
    assert "message" in choice
    assert "finish_reason" in choice
    assert choice["finish_reason"] in ("stop", "length", "content_filter", "tool_calls")
    assert "usage" in data
    for f in ["prompt_tokens", "completion_tokens", "total_tokens"]:
        assert f in data["usage"]
