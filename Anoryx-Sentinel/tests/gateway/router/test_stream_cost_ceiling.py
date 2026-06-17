"""HIGH-1 regression: stream-time cost ceiling enforcement (threat #3, ADR §7.4).

The pre-request cost check in route_stream only bounds the ESTIMATE before the
first byte. A stream that overruns its estimate at generation time must still be
stopped. _handle_stream now threads the committed (provider, model) and the
tenant cost_ceiling_cents out of route_stream via a StreamRouteResult holder, and
recomputes a running client-side cost estimate from accumulated tokens on every
chunk. On breach it emits a policy_blocked SSE error frame, a best-effort
cost_blocked routing_decision audit event, and closes WITHOUT [DONE] — mirroring
the F-005 streaming-block fail-safe shape.

These tests drive _handle_stream with a stubbed route_stream that commits a
provider+model+ceiling on the holder and then drip-feeds content chunks past the
low ceiling, asserting the fail-safe frame, the absence of [DONE], and the audit.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from gateway.config import get_settings
from gateway.context import TenantContext
from gateway.models import CreateChatCompletionRequest
from gateway.router.selection import StreamRouteResult
from gateway.routes.chat_completions import _handle_stream

_TENANT = TenantContext(
    tenant_id="t-1",
    team_id="team-1",
    project_id="proj-1",
    agent_id="gateway-core",
    virtual_key_id="key-1",
)


def _content_chunk(words: str) -> str:
    import json

    payload = {"choices": [{"delta": {"content": words}}]}
    return f"data: {json.dumps(payload)}\n"


async def _drain(response) -> str:
    parts = []
    async for piece in response.body_iterator:
        parts.append(piece if isinstance(piece, str) else piece.decode())
    return "".join(parts)


def _make_validated(**overrides) -> CreateChatCompletionRequest:
    data = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello world"}],
        "stream": True,
    }
    data.update(overrides)
    return CreateChatCompletionRequest(**data)


@pytest.mark.asyncio
async def test_stream_running_cost_breach_blocks(settings_env):
    """A stream whose running estimate exceeds the ceiling is stopped with a
    policy_blocked frame, no [DONE], and a cost_blocked audit emission."""

    # Fake route_stream: commit an expensive provider/model with a tiny ceiling,
    # then drip-feed many output words so the running estimate breaches it.
    async def _fake_route_stream(*, result: StreamRouteResult, **kwargs):
        result.resolved_provider = "openai"
        result.resolved_model = "gpt-4o"
        result.cost_ceiling_cents = 0.001  # tiny ceiling — breached quickly
        # gpt-4o out-rate is 1.0 cents/1k tokens; ~50 words easily exceeds 0.001.
        for _ in range(50):
            yield _content_chunk("alpha beta gamma delta epsilon")
        # If we ever reached here without blocking, the stream would DONE.
        yield "data: [DONE]\n"

    audit_events: list[dict] = []

    async def _capture_audit(**kwargs):
        audit_events.append(kwargs)

    with (
        patch("gateway.routes.chat_completions.route_stream", new=_fake_route_stream),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
        patch("gateway.middleware.audit.emit_routing_decision", new=_capture_audit),
    ):
        response = await _handle_stream(
            validated=_make_validated(),
            request_id="req-cost-stream",
            tenant_context=_TENANT,
            start_time=0.0,
            rl_limit=10,
            rl_remaining=9,
            rl_reset=0,
            upstream_api_key=None,
            settings=get_settings(),
            hook_registry=None,
            hook_context=None,
            provider_registry=object(),  # not used: route_stream is stubbed
        )
        body = await _drain(response)

    assert "event: error" in body
    assert "policy_blocked" in body
    assert "[DONE]" not in body  # stream closed WITHOUT [DONE]
    # A cost_blocked routing_decision audit event was emitted (best-effort).
    assert any(
        e.get("outcome") == "cost_blocked" and e.get("action_taken") == "blocked"
        for e in audit_events
    )


@pytest.mark.asyncio
async def test_stream_under_ceiling_completes_with_done(settings_env):
    """A stream whose running estimate stays under the ceiling is NOT blocked."""

    async def _fake_route_stream(*, result: StreamRouteResult, **kwargs):
        result.resolved_provider = "openai"
        result.resolved_model = "gpt-4o"
        result.cost_ceiling_cents = 1_000_000.0  # effectively unbounded
        yield _content_chunk("hello there")
        yield "data: [DONE]\n"

    with (
        patch("gateway.routes.chat_completions.route_stream", new=_fake_route_stream),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
    ):
        response = await _handle_stream(
            validated=_make_validated(),
            request_id="req-cost-stream-ok",
            tenant_context=_TENANT,
            start_time=0.0,
            rl_limit=10,
            rl_remaining=9,
            rl_reset=0,
            upstream_api_key=None,
            settings=get_settings(),
            hook_registry=None,
            hook_context=None,
            provider_registry=object(),
        )
        body = await _drain(response)

    assert "[DONE]" in body
    assert "policy_blocked" not in body


@pytest.mark.asyncio
async def test_stream_no_ceiling_never_blocks(settings_env):
    """When the tenant has no cost_ceiling_cents, the running check is skipped."""

    async def _fake_route_stream(*, result: StreamRouteResult, **kwargs):
        result.resolved_provider = "openai"
        result.resolved_model = "gpt-4o"
        result.cost_ceiling_cents = None  # no ceiling
        for _ in range(50):
            yield _content_chunk("alpha beta gamma delta epsilon")
        yield "data: [DONE]\n"

    with (
        patch("gateway.routes.chat_completions.route_stream", new=_fake_route_stream),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
    ):
        response = await _handle_stream(
            validated=_make_validated(),
            request_id="req-cost-stream-none",
            tenant_context=_TENANT,
            start_time=0.0,
            rl_limit=10,
            rl_remaining=9,
            rl_reset=0,
            upstream_api_key=None,
            settings=get_settings(),
            hook_registry=None,
            hook_context=None,
            provider_registry=object(),
        )
        body = await _drain(response)

    assert "[DONE]" in body
    assert "policy_blocked" not in body
