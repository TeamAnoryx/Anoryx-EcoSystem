"""OpenAI adapter delegate tests (F-006, ADR-0008 §2.3).

The OpenAI adapter delegates to the existing proxy_non_stream /
_proxy_stream_generator. Its only addition is mapping GatewayError -> transient
ProviderError so the fallback layer can decide retry vs terminal.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from gateway.exceptions import GatewayError
from gateway.models import ChatCompletionResponse
from gateway.router.exceptions import ProviderError
from gateway.router.providers.openai_provider import OpenAiAdapter
from tests.gateway.router.conftest import make_body, make_ctx

_RESP = ChatCompletionResponse(
    id="chatcmpl-x",
    object="chat.completion",
    created=1,
    model="gpt-3.5-turbo",
    choices=[
        {  # type: ignore[list-item]
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": "stop",
        }
    ],
    usage={"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},  # type: ignore[arg-type]
)


@pytest.mark.asyncio
async def test_complete_delegates_and_returns_tuple(settings_env):
    with patch(
        "gateway.router.providers.openai_provider.proxy_non_stream",
        new=AsyncMock(return_value=(_RESP, 3, 1)),
    ):
        adapter = OpenAiAdapter(stream_timeout=30.0)
        completion, tin, tout = await adapter.complete(
            make_body(model="gpt-3.5-turbo"), make_ctx("openai", "gpt-3.5-turbo")
        )
    assert completion.id == "chatcmpl-x"
    assert (tin, tout) == (3, 1)


@pytest.mark.asyncio
async def test_gateway_error_maps_to_transient(settings_env):
    with patch(
        "gateway.router.providers.openai_provider.proxy_non_stream",
        new=AsyncMock(side_effect=GatewayError("internal_error")),
    ):
        adapter = OpenAiAdapter(stream_timeout=30.0)
        with pytest.raises(ProviderError) as ei:
            await adapter.complete(make_body(), make_ctx("openai", "gpt-3.5-turbo"))
    assert ei.value.kind == "transient"
    assert ei.value.is_retryable is True


# ---------------------------------------------------------------------------
# MEDIUM-1: 401/403 must classify as TERMINAL auth (NOT retryable); 5xx stays
# transient (retryable). openai_proxy attaches the upstream status additively.
# ---------------------------------------------------------------------------


def _gw_error_with_status(status: int) -> GatewayError:
    """A GatewayError mirroring openai_proxy's additive upstream_status attr."""
    exc = GatewayError("internal_error")
    exc.upstream_status = status  # type: ignore[attr-defined]
    return exc


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_openai_auth_status_maps_to_auth_terminal(settings_env, status):
    with patch(
        "gateway.router.providers.openai_provider.proxy_non_stream",
        new=AsyncMock(side_effect=_gw_error_with_status(status)),
    ):
        adapter = OpenAiAdapter(stream_timeout=30.0)
        with pytest.raises(ProviderError) as ei:
            await adapter.complete(make_body(), make_ctx("openai", "gpt-3.5-turbo"))
    # 401/403 -> auth, which is TERMINAL (never retried by the §6 fallback loop).
    assert ei.value.kind == "auth"
    assert ei.value.is_retryable is False


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 502, 503])
async def test_openai_5xx_status_stays_transient(settings_env, status):
    with patch(
        "gateway.router.providers.openai_provider.proxy_non_stream",
        new=AsyncMock(side_effect=_gw_error_with_status(status)),
    ):
        adapter = OpenAiAdapter(stream_timeout=30.0)
        with pytest.raises(ProviderError) as ei:
            await adapter.complete(make_body(), make_ctx("openai", "gpt-3.5-turbo"))
    # 5xx remains transient so a generic upstream failure still fails over.
    assert ei.value.kind == "transient"
    assert ei.value.is_retryable is True


@pytest.mark.asyncio
async def test_openai_missing_status_defaults_transient(settings_env):
    # No upstream_status attribute (unknown cause: connect/timeout) -> transient.
    with patch(
        "gateway.router.providers.openai_provider.proxy_non_stream",
        new=AsyncMock(side_effect=GatewayError("internal_error")),
    ):
        adapter = OpenAiAdapter(stream_timeout=30.0)
        with pytest.raises(ProviderError) as ei:
            await adapter.complete(make_body(), make_ctx("openai", "gpt-3.5-turbo"))
    assert ei.value.kind == "transient"
    assert ei.value.is_retryable is True


@pytest.mark.asyncio
async def test_openai_401_not_retried_by_fallback_loop(settings_env):
    """End-to-end: a real OpenAiAdapter 401 must NOT fall over to a next provider.

    Proves the MEDIUM-1 fix at the fallback-loop boundary: openai_proxy attaches
    upstream_status=401, the adapter maps it to auth, and route_non_stream treats
    auth as TERMINAL (anthropic is allowed+next but never tried) -> 500.
    """
    from unittest.mock import patch as _patch

    from gateway.config import get_settings
    from gateway.context import TenantContext
    from gateway.router.selection import route_non_stream
    from persistence.repositories.tenant_routing_policy_repository import EffectiveRoutingPolicy

    tenant = TenantContext(
        tenant_id="t-1",
        team_id="team-1",
        project_id="proj-1",
        agent_id="gateway-core",
        virtual_key_id="key-1",
    )
    policy = EffectiveRoutingPolicy(
        tenant_id="t-1",
        allowed_providers=["openai", "anthropic"],
        fallback_order=["openai", "anthropic"],
        cost_ceiling_cents=None,
        is_default=False,
    )

    anthropic_tried = {"calls": 0}

    class _AnthropicSpy:
        name = "anthropic"

        async def complete(self, body, ctx):
            anthropic_tried["calls"] += 1
            from gateway.models import ChatCompletionResponse

            return (
                ChatCompletionResponse(
                    id="x",
                    object="chat.completion",
                    created=1,
                    model="m",
                    choices=[
                        {  # type: ignore[list-item]
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                    usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},  # type: ignore[arg-type]
                ),
                1,
                1,
            )

        async def stream(self, body, ctx):  # pragma: no cover
            yield "data: [DONE]\n"

    class _Reg:
        def __init__(self):
            self._a = {"openai": OpenAiAdapter(stream_timeout=30.0), "anthropic": _AnthropicSpy()}

        def available_providers(self):
            return set(self._a)

        def get(self, name):
            return self._a.get(name)

    async def _fake_resolve(tc):
        return policy

    async def _fake_emit(**kwargs):
        pass

    with (
        _patch(
            "gateway.router.providers.openai_provider.proxy_non_stream",
            new=AsyncMock(side_effect=_gw_error_with_status(401)),
        ),
        _patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        _patch("gateway.router.selection.emit_routing_decision", new=_fake_emit),
    ):
        with pytest.raises(GatewayError) as ei:
            await route_non_stream(
                validated_body=make_body(model="gpt-3.5-turbo"),
                request_id="req-1",
                tenant_context=tenant,
                registry=_Reg(),
                settings=get_settings(),
            )
    assert ei.value.error_code == "internal_error"  # 500, not a fallback success
    assert anthropic_tried["calls"] == 0  # auth TERMINAL — never retried


@pytest.mark.asyncio
async def test_stream_delegates_lines(settings_env):
    async def _fake_gen(**kwargs):
        yield 'data: {"choices":[{"delta":{"content":"hi"}}]}\n'
        yield "data: [DONE]\n"

    with patch(
        "gateway.router.providers.openai_provider._proxy_stream_generator",
        new=_fake_gen,
    ):
        adapter = OpenAiAdapter(stream_timeout=30.0)
        lines = [
            line
            async for line in adapter.stream(
                make_body(stream=True), make_ctx("openai", "gpt-3.5-turbo")
            )
        ]
    assert lines[-1].strip() == "data: [DONE]"
