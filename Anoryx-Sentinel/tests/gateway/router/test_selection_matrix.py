"""Fallback / terminal matrix tests for the router (F-006, ADR-0008 §6).

These pin the SECURITY boundary the matrix defines:
  - transient / 429 retried (fall over to next allowed provider),
  - 401/403 auth TERMINAL (never retried) -> 500,
  - content_policy 4xx TERMINAL (never retried) -> 500,
  - allow-list deny TERMINAL + audit -> 403 policy_blocked,
  - cost breach TERMINAL + audit -> 403 policy_blocked,
  - exhaustion -> 500 internal_error,
  - one shared budget + router_max_fallbacks cap.

The tenant policy read and the routing_decision audit emit are stubbed (no DB).
A captured list records every emitted routing_decision so we assert audit fires.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from gateway.config import get_settings
from gateway.context import TenantContext
from gateway.exceptions import GatewayError
from gateway.models import ChatCompletionResponse
from gateway.router.exceptions import ProviderError
from gateway.router.selection import route_non_stream, route_stream
from persistence.repositories.tenant_routing_policy_repository import EffectiveRoutingPolicy
from policy.enforcement import BudgetOk, ModelAllow
from tests.gateway.router.conftest import make_body

_TENANT = TenantContext(
    tenant_id="t-1",
    team_id="team-1",
    project_id="proj-1",
    agent_id="gateway-core",
    virtual_key_id="key-1",
)


# F-008 (ADR-0009 §6): the router now runs a model + budget enforcement step before
# the F-006 tenant_routing_policy. These matrix tests pin the F-006 fallback/cost
# boundary, so they stub the F-008 gate to "allow, no budgets" (its own behavior is
# covered by tests/policy/), exactly as they stub _resolve_policy + emit_routing_decision.
async def _allow_enforce(tenant_context, body):
    return ModelAllow(None), BudgetOk(), []


async def _noop_policy_decision(*args, **kwargs):
    return None


def _resp(model="m"):
    return ChatCompletionResponse(
        id="chatcmpl-x",
        object="chat.completion",
        created=1,
        model=model,
        choices=[
            {  # type: ignore[list-item]
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }
        ],
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},  # type: ignore[arg-type]
    )


class _FakeAdapter:
    """Adapter whose complete/stream behavior is scripted per provider."""

    def __init__(self, name, *, raises=None, resp=None, stream_lines=None, stream_raises=None):
        self.name = name
        self._raises = raises
        self._resp = resp
        self._stream_lines = stream_lines or [
            'data: {"choices":[{"delta":{"content":"x"}}]}\n',
            "data: [DONE]\n",
        ]
        self._stream_raises = stream_raises
        self.complete_calls = 0
        self.stream_calls = 0

    async def complete(self, body, ctx):
        self.complete_calls += 1
        if self._raises is not None:
            raise self._raises
        return (self._resp or _resp(ctx.resolved_model)), 1, 1

    async def stream(self, body, ctx):
        self.stream_calls += 1
        if self._stream_raises is not None:
            raise self._stream_raises
        for ln in self._stream_lines:
            yield ln


class _FakeRegistry:
    def __init__(self, adapters: dict[str, _FakeAdapter]):
        self._adapters = adapters

    def available_providers(self):
        return set(self._adapters.keys())

    def get(self, name):
        return self._adapters.get(name)


def _policy(allowed, order, ceiling=None, is_default=False):
    return EffectiveRoutingPolicy(
        tenant_id="t-1",
        allowed_providers=allowed,
        fallback_order=order,
        cost_ceiling_cents=ceiling,
        is_default=is_default,
    )


async def _run_non_stream(policy, registry, body=None, events=None):
    body = body or make_body(model="m")

    async def _fake_resolve(tenant_context):
        return policy

    async def _fake_emit(**kwargs):
        if events is not None:
            events.append(kwargs)

    with (
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=_fake_emit),
        patch("gateway.router.selection._enforce_policies_pre_request", new=_allow_enforce),
        patch("gateway.router.selection.emit_policy_decision", new=_noop_policy_decision),
    ):
        return await route_non_stream(
            validated_body=body,
            request_id="req-1",
            tenant_context=_TENANT,
            registry=registry,
            settings=get_settings(),
        )


async def _collect_stream(policy, registry, body=None, events=None):
    body = body or make_body(model="m", stream=True)

    async def _fake_resolve(tenant_context):
        return policy

    async def _fake_emit(**kwargs):
        if events is not None:
            events.append(kwargs)

    with (
        patch("gateway.router.selection._resolve_policy", new=_fake_resolve),
        patch("gateway.router.selection.emit_routing_decision", new=_fake_emit),
        patch("gateway.router.selection._enforce_policies_pre_request", new=_allow_enforce),
        patch("gateway.router.selection.emit_policy_decision", new=_noop_policy_decision),
    ):
        lines = []
        async for line in route_stream(
            validated_body=body,
            request_id="req-1",
            tenant_context=_TENANT,
            registry=registry,
            settings=get_settings(),
        ):
            lines.append(line)
        return lines


# ---------------------------------------------------------------------------
# Happy path / OpenAI-only behavior identical to today.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openai_only_single_attempt_selected(settings_env):
    oa = _FakeAdapter("openai", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa})
    events = []
    completion, tin, tout = await _run_non_stream(
        _policy(["openai"], ["openai"], is_default=True), reg, events=events
    )
    assert completion.object == "chat.completion"
    assert oa.complete_calls == 1
    # Exactly one 'selected' routing_decision.
    selected = [e for e in events if e["outcome"] == "selected"]
    assert len(selected) == 1 and selected[0]["action_taken"] == "routed"
    assert selected[0]["selected_provider"] == "openai"


# ---------------------------------------------------------------------------
# Retryable: transient + 429 -> fall over to next provider.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transient_falls_over_to_next(settings_env):
    oa = _FakeAdapter("openai", raises=ProviderError("transient"))
    an = _FakeAdapter("anthropic", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    events = []
    completion, _, _ = await _run_non_stream(
        _policy(["openai", "anthropic"], ["openai", "anthropic"]), reg, events=events
    )
    assert oa.complete_calls == 1 and an.complete_calls == 1
    assert completion.object == "chat.completion"
    assert any(
        e["outcome"] == "fallback_attempted" and e["action_taken"] == "failed_over" for e in events
    )
    assert any(e["outcome"] == "selected" and e["selected_provider"] == "anthropic" for e in events)


@pytest.mark.asyncio
async def test_rate_limited_retried(settings_env):
    oa = _FakeAdapter("openai", raises=ProviderError("rate_limited", status=429))
    an = _FakeAdapter("anthropic", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    completion, _, _ = await _run_non_stream(
        _policy(["openai", "anthropic"], ["openai", "anthropic"]), reg
    )
    assert an.complete_calls == 1


# ---------------------------------------------------------------------------
# TERMINAL — never retried: auth (401/403), content_policy.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_is_terminal_never_retried(settings_env):
    oa = _FakeAdapter("openai", raises=ProviderError("auth", status=401))
    an = _FakeAdapter("anthropic", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    events = []
    with pytest.raises(GatewayError) as ei:
        await _run_non_stream(
            _policy(["openai", "anthropic"], ["openai", "anthropic"]), reg, events=events
        )
    assert ei.value.error_code == "internal_error"  # 500
    # Auth must NOT fall over to anthropic.
    assert an.complete_calls == 0
    assert any(e["outcome"] == "exhausted" for e in events)


@pytest.mark.asyncio
async def test_content_policy_is_terminal_never_retried(settings_env):
    oa = _FakeAdapter("openai", raises=ProviderError("content_policy", status=400))
    an = _FakeAdapter("anthropic", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    with pytest.raises(GatewayError) as ei:
        await _run_non_stream(_policy(["openai", "anthropic"], ["openai", "anthropic"]), reg)
    assert ei.value.error_code == "internal_error"
    assert an.complete_calls == 0


# ---------------------------------------------------------------------------
# Allow-list deny — TERMINAL + audit -> 403 policy_blocked, never silent fallback.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allowlist_deny_blocks_403_with_audit(settings_env):
    # Tenant allows ONLY anthropic, but anthropic is unavailable -> empty chain.
    an = _FakeAdapter("anthropic", resp=_resp("m"))
    reg = _FakeRegistry({"openai": _FakeAdapter("openai", resp=_resp("m"))})
    events = []
    with pytest.raises(GatewayError) as ei:
        await _run_non_stream(_policy(["anthropic"], ["anthropic"]), reg, events=events)
    assert ei.value.error_code == "policy_blocked"  # 403
    assert any(
        e["outcome"] == "allowlist_denied" and e["action_taken"] == "blocked" for e in events
    )
    assert an.complete_calls == 0


# ---------------------------------------------------------------------------
# Cost breach — TERMINAL + audit -> 403, no silent downgrade.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cost_breach_blocks_403_with_audit(settings_env):
    oa = _FakeAdapter("openai", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa})
    events = []
    # Ceiling of 0.0 cents is breached by any non-empty estimate.
    with pytest.raises(GatewayError) as ei:
        await _run_non_stream(
            _policy(["openai"], ["openai"], ceiling=0.0),
            reg,
            body=make_body(model="gpt-4o", max_tokens=5000),
            events=events,
        )
    assert ei.value.error_code == "policy_blocked"
    assert any(e["outcome"] == "cost_blocked" and e["action_taken"] == "blocked" for e in events)
    # No upstream call happened — blocked pre-request.
    assert oa.complete_calls == 0


@pytest.mark.asyncio
async def test_cost_under_ceiling_proceeds(settings_env):
    oa = _FakeAdapter("openai", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa})
    completion, _, _ = await _run_non_stream(
        _policy(["openai"], ["openai"], ceiling=1_000_000.0),
        reg,
        body=make_body(model="gpt-3.5-turbo", max_tokens=10),
    )
    assert completion.object == "chat.completion"
    assert oa.complete_calls == 1


# ---------------------------------------------------------------------------
# Exhaustion -> 500.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exhaustion_returns_500(settings_env):
    oa = _FakeAdapter("openai", raises=ProviderError("transient"))
    an = _FakeAdapter("anthropic", raises=ProviderError("transient"))
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    events = []
    with pytest.raises(GatewayError) as ei:
        await _run_non_stream(
            _policy(["openai", "anthropic"], ["openai", "anthropic"]), reg, events=events
        )
    assert ei.value.error_code == "internal_error"
    assert any(e["outcome"] == "exhausted" for e in events)


# ---------------------------------------------------------------------------
# router_max_fallbacks cap.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_max_fallbacks_caps_attempts(settings_env, monkeypatch):
    monkeypatch.setenv("ROUTER_MAX_FALLBACKS", "0")  # only 1 attempt allowed
    from gateway.config import _reset_settings

    _reset_settings()
    oa = _FakeAdapter("openai", raises=ProviderError("transient"))
    an = _FakeAdapter("anthropic", resp=_resp("m"))
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    with pytest.raises(GatewayError):
        await _run_non_stream(_policy(["openai", "anthropic"], ["openai", "anthropic"]), reg)
    # Cap = 1 total attempt: anthropic never tried despite being allowed.
    assert oa.complete_calls == 1
    assert an.complete_calls == 0
    _reset_settings()


# ---------------------------------------------------------------------------
# Streaming: terminal block before first byte -> policy_blocked error frame.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_cost_block_emits_error_frame_no_done(settings_env):
    oa = _FakeAdapter("openai")
    reg = _FakeRegistry({"openai": oa})
    lines = await _collect_stream(
        _policy(["openai"], ["openai"], ceiling=0.0),
        reg,
        body=make_body(model="gpt-4o", max_tokens=9000, stream=True),
    )
    joined = "".join(lines)
    assert "event: error" in joined
    assert "policy_blocked" in joined
    assert "[DONE]" not in joined


@pytest.mark.asyncio
async def test_stream_transient_falls_over_before_first_byte(settings_env):
    oa = _FakeAdapter("openai", stream_raises=ProviderError("transient"))
    an = _FakeAdapter("anthropic")
    reg = _FakeRegistry({"openai": oa, "anthropic": an})
    lines = await _collect_stream(
        _policy(["openai", "anthropic"], ["openai", "anthropic"]),
        reg,
        body=make_body(model="m", stream=True),
    )
    joined = "".join(lines)
    assert "[DONE]" in joined  # anthropic succeeded after openai failed pre-byte
    assert an.stream_calls == 1
