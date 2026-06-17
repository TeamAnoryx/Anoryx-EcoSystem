"""F-008 enforcement wiring through the F-006 router (ADR-0009 §6).

These prove the INTEGRATION: the model/budget gate runs BEFORE tenant routing, a
deny is terminal (policy_blocked, no fallback), an allow emits policy_decision_allow
and proceeds, and the stream path yields a policy_blocked frame on deny. The gate's
own decision LOGIC is covered in tests/policy/test_variants.py; here we stub the
gate's result and assert the router's response + emitted events. Mid-stream budget
termination is exercised end-to-end by the threat-model suite (threat #14).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from gateway.config import get_settings
from gateway.context import TenantContext
from gateway.exceptions import GatewayError
from gateway.models import ChatCompletionResponse
from persistence.repositories.tenant_routing_policy_repository import EffectiveRoutingPolicy
from policy.enforcement import BudgetExceeded, BudgetOk, ModelAllow, ModelDeny
from tests.gateway.router.conftest import make_body

_TENANT = TenantContext(
    tenant_id="11111111-1111-1111-1111-111111111111",
    team_id="22222222-2222-2222-2222-222222222222",
    project_id="33333333-3333-3333-3333-333333333333",
    agent_id="gateway-core",
    virtual_key_id="key-1",
)


def _resp():
    return ChatCompletionResponse(
        id="chatcmpl-x",
        object="chat.completion",
        created=1,
        model="gpt-4o",
        choices=[
            {  # type: ignore[list-item]
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }
        ],
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},  # type: ignore[arg-type]
    )


class _Adapter:
    name = "openai"

    async def complete(self, body, ctx):
        return _resp(), 1, 1

    async def stream(self, body, ctx):
        yield 'data: {"choices":[{"delta":{"content":"x"}}]}\n'
        yield "data: [DONE]\n"


class _Reg:
    def available_providers(self):
        return {"openai"}

    def get(self, name):
        return _Adapter() if name == "openai" else None


async def _fake_resolve(tenant_context):
    return EffectiveRoutingPolicy(
        tenant_id=tenant_context.tenant_id,
        allowed_providers=["openai"],
        fallback_order=["openai"],
        cost_ceiling_cents=None,
        is_default=True,
    )


def _gate(model_decision, budget_decision=None, budgets=None):
    async def _enforce(tenant_context, body):
        return model_decision, budget_decision or BudgetOk(), budgets or []

    return _enforce


@pytest.mark.asyncio
async def test_model_deny_is_terminal_non_stream(settings_env):
    emit = AsyncMock()
    with (
        patch(
            "gateway.router.selection._enforce_policies_pre_request",
            new=_gate(ModelDeny("pid-deny", "model_denied")),
        ),
        patch("gateway.router.selection.emit_policy_decision", new=emit),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
    ):
        with pytest.raises(GatewayError) as ei:
            await route_non_stream_call()
    assert ei.value.error_code == "policy_blocked"
    emit.assert_awaited_once()
    kwargs = emit.call_args.kwargs
    assert kwargs["allow"] is False
    assert kwargs["policy_id"] == "pid-deny"
    assert kwargs["reason"] == "model_denied"


@pytest.mark.asyncio
async def test_budget_exceeded_is_terminal_non_stream(settings_env):
    emit = AsyncMock()
    with (
        patch(
            "gateway.router.selection._enforce_policies_pre_request",
            new=_gate(ModelAllow(None), BudgetExceeded("pid-bud", "budget_tokens_exceeded")),
        ),
        patch("gateway.router.selection.emit_policy_decision", new=emit),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
    ):
        with pytest.raises(GatewayError) as ei:
            await route_non_stream_call()
    assert ei.value.error_code == "policy_blocked"
    kwargs = emit.call_args.kwargs
    assert kwargs["allow"] is False and kwargs["reason"] == "budget_tokens_exceeded"


@pytest.mark.asyncio
async def test_model_allow_emits_and_proceeds(settings_env):
    emit = AsyncMock()
    with (
        patch(
            "gateway.router.selection._enforce_policies_pre_request",
            new=_gate(ModelAllow("pid-allow")),
        ),
        patch("gateway.router.selection.emit_policy_decision", new=emit),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
    ):
        completion, _tin, _tout = await route_non_stream_call()
    assert completion.object == "chat.completion"
    emit.assert_awaited_once()
    kwargs = emit.call_args.kwargs
    assert kwargs["allow"] is True and kwargs["policy_id"] == "pid-allow"


@pytest.mark.asyncio
async def test_no_matching_policy_does_not_emit(settings_env):
    """ModelAllow(None) (no policy matched) proceeds with NO policy_decision event."""
    emit = AsyncMock()
    with (
        patch(
            "gateway.router.selection._enforce_policies_pre_request",
            new=_gate(ModelAllow(None)),
        ),
        patch("gateway.router.selection.emit_policy_decision", new=emit),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
    ):
        completion, _tin, _tout = await route_non_stream_call()
    assert completion.object == "chat.completion"
    emit.assert_not_awaited()


@pytest.mark.asyncio
async def test_model_deny_is_terminal_stream(settings_env):
    emit = AsyncMock()
    with (
        patch(
            "gateway.router.selection._enforce_policies_pre_request",
            new=_gate(ModelDeny("pid-deny", "model_denied")),
        ),
        patch("gateway.router.selection.emit_policy_decision", new=emit),
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
    ):
        lines = await route_stream_collect()
    joined = "".join(lines)
    assert "event: error" in joined
    assert "policy_blocked" in joined
    assert "[DONE]" not in joined
    kwargs = emit.call_args.kwargs
    assert kwargs["allow"] is False


@pytest.mark.asyncio
async def test_budget_exhaustion_mid_stream_terminates(settings_env):
    """Threat #14: a budget ceiling hit mid-stream terminates at the chunk boundary
    with a policy_blocked frame and NO [DONE] (same primitive as the §7.4 cost ceiling).
    """
    import time
    from contextlib import asynccontextmanager

    from gateway.routes.chat_completions import _handle_stream
    from policy.variants import BudgetLimitPolicy

    budget = BudgetLimitPolicy(
        policy_id="bpid",
        tenant_id=_TENANT.tenant_id,
        team_id=_TENANT.team_id,
        project_id=_TENANT.project_id,
        agent_id="gateway-core",
        policy_version=1,
        period="daily",
        scope="tenant",
        max_tokens_per_period=3,
    )

    async def _fake_route_stream(
        *, validated_body, request_id, tenant_context, registry, settings, result=None
    ):
        if result is not None:
            result.resolved_provider = "openai"
            result.resolved_model = "gpt-4o"
            result.budgets = [(budget, 2, 0.0)]  # baseline used=2 tokens; ceiling=3
        yield 'data: {"choices":[{"delta":{"content":"alpha beta"}}]}\n'
        yield "data: [DONE]\n"

    @asynccontextmanager
    async def _noop_slot(tenant_id):
        yield

    emit = AsyncMock()
    with (
        patch("gateway.routes.chat_completions.route_stream", new=_fake_route_stream),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
        patch("gateway.routes.chat_completions.stream_slot", new=_noop_slot),
        patch("policy.audit_events.emit_policy_decision", new=emit),
    ):
        resp = await _handle_stream(
            validated=make_body(model="gpt-4o", stream=True),
            request_id="req-budget",
            tenant_context=_TENANT,
            start_time=time.monotonic(),
            rl_limit=600,
            rl_remaining=599,
            rl_reset=0,
            upstream_api_key=None,
            settings=get_settings(),
            provider_registry=_Reg(),
        )
        chunks = [c async for c in resp.body_iterator]

    joined = "".join(chunks)
    assert "event: error" in joined
    assert "policy_blocked" in joined
    assert "[DONE]" not in joined  # terminated mid-stream, no normal completion
    emit.assert_awaited_once()
    assert emit.call_args.kwargs["allow"] is False
    assert emit.call_args.kwargs["reason"] in (
        "budget_tokens_exceeded",
        "budget_cost_exceeded",
    )


def test_prompt_token_proxy_scales_with_n(settings_env):
    """The pre-request budget token proxy scales output by n (1-8 parallel completions)
    so an n>1 request cannot under-count past the budget gate (security-auditor MED).
    """
    from gateway.router.selection import _prompt_token_proxy

    base = _prompt_token_proxy(make_body(model="gpt-4o", max_tokens=100))  # n defaults to 1
    scaled = _prompt_token_proxy(make_body(model="gpt-4o", max_tokens=100, n=8))
    assert scaled - base == 100 * 7  # n=8 adds 7 extra copies of the 100-token output


# --- thin call helpers (import inside to honor the patched module attrs) ---
async def route_non_stream_call():
    from gateway.router.selection import route_non_stream

    return await route_non_stream(
        validated_body=make_body(model="gpt-4o"),
        request_id="req-pol-1",
        tenant_context=_TENANT,
        registry=_Reg(),
        settings=get_settings(),
    )


async def route_stream_collect():
    from gateway.router.selection import route_stream

    lines = []
    async for line in route_stream(
        validated_body=make_body(model="gpt-4o", stream=True),
        request_id="req-pol-1",
        tenant_context=_TENANT,
        registry=_Reg(),
        settings=get_settings(),
    ):
        lines.append(line)
    return lines
