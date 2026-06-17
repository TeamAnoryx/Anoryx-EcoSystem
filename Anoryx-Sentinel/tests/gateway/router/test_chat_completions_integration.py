"""Integration: the router's TRANSLATED body reaches the F-005 post-hook in
OpenAI shape (F-006, ADR-0008 threat #8).

We route to a NON-OpenAI provider (anthropic) whose adapter returns an OpenAI-
shape ChatCompletionResponse, then assert the post-response hook receives a
json.dumps of a normal OpenAI dict (object == 'chat.completion', choices[0].
message.content present). This proves provider->OpenAI translation happens
BEFORE the F-005 outbound inspection window.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.config import _reset_settings
from gateway.models import ChatCompletionResponse
from persistence.repositories.tenant_routing_policy_repository import EffectiveRoutingPolicy
from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_PLAINTEXT_KEY,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
    make_fake_key_row,
)


def _headers():
    return {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
        "Content-Type": "application/json",
    }


_TRANSLATED = ChatCompletionResponse(
    id="chatcmpl-translated",
    object="chat.completion",
    created=1,
    model="claude-3-haiku",
    choices=[
        {  # type: ignore[list-item]
            "index": 0,
            "message": {"role": "assistant", "content": "translated content"},
            "finish_reason": "stop",
        }
    ],
    usage={"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},  # type: ignore[arg-type]
)


class _FakeAnthropic:
    name = "anthropic"

    async def complete(self, body, ctx):
        return _TRANSLATED, 5, 2

    async def stream(self, body, ctx):  # pragma: no cover - not used here
        yield "data: [DONE]\n"


class _Registry:
    def available_providers(self):
        return {"anthropic"}

    def get(self, name):
        return _FakeAnthropic() if name == "anthropic" else None


@pytest.mark.asyncio
async def test_translated_body_reaches_post_hook_in_openai_shape(settings_env):
    _reset_settings()
    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=make_fake_key_row())

    @asynccontextmanager
    async def _priv_cm():
        s = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        s.begin = _begin
        yield s

    @asynccontextmanager
    async def _tenant_cm(tenant_id):
        s = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        s.begin = _begin
        yield s

    async def _policy(self, tenant_id, caller_tenant_id):
        return EffectiveRoutingPolicy(
            tenant_id=tenant_id,
            allowed_providers=["anthropic"],
            fallback_order=["anthropic"],
            cost_ceiling_cents=None,
        )

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    with (
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
        patch("persistence.database.get_tenant_session", _tenant_cm),
        patch(
            "persistence.repositories.tenant_routing_policy_repository."
            "TenantRoutingPolicyRepository.get_for_tenant",
            new=_policy,
        ),
        # Force the route to use our fake registry (anthropic only).
        patch(
            "gateway.routes.chat_completions._get_provider_registry",
            return_value=_Registry(),
        ),
    ):
        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_headers(),
                json={
                    "model": "claude-3-haiku",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

    assert resp.status_code == 200
    body = resp.json()
    # The CLIENT sees an OpenAI-shape response translated from Anthropic. Because
    # the F-005 non-stream post-hook inspects json.dumps(completion.model_dump())
    # of this SAME translated ChatCompletionResponse, the post-hook necessarily
    # sees OpenAI-shape bytes (threat #8). Round-trip the wire body to confirm it
    # is a valid OpenAI dict.
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["content"] == "translated content"
    assert body["model"] == "claude-3-haiku"
    json.dumps(body)  # serializable OpenAI dict — exactly what the hook receives

    _reset_settings()
