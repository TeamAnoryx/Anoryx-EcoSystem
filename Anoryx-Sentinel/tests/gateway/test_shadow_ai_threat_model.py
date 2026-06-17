"""F-007 shadow-AI threat model — 3 vectors (ADR-0010 §9, vectors 11-13).

Vectors 11-12 prove the egress monitor detects disallowed-provider egress and
stays silent for allowed egress. Vector 13 is an HONEST-LIMITATION test: traffic
that bypasses Sentinel's own httpx clients (network-layer bypass, or Bedrock via
aioboto3) never invokes the hook and is therefore undetected — documented, not a
claimed capability (ADR-0010 §12.1).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from gateway.context import EgressContext, TenantContext, current_egress_context
from gateway.middleware.egress_monitor import egress_request_hook, resolve_provider

TC = TenantContext(
    tenant_id="t-1", team_id="tm-1", project_id="p-1", agent_id="a-1", virtual_key_id="k-1"
)


@pytest.fixture(autouse=True)
def _clear_egress():
    yield
    current_egress_context.set(None)


async def test_disallowed_egress_emits_shadow_ai_detected(monkeypatch):
    # Vector 11: egress to a provider NOT in the tenant allow-list → a
    # shadow_ai_detected_outbound event is appended (proves detection + correct event).
    from orchestration.context import HookContext

    emit = AsyncMock(return_value=True)
    monkeypatch.setattr(HookContext, "emit", emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("anthropic",)))  # openai NOT allowed
    await egress_request_hook(httpx.Request("POST", "https://api.openai.com/v1/chat/completions"))
    emit.assert_awaited_once()
    event, kwargs = emit.call_args.args[0], emit.call_args.kwargs
    assert event["event_type"] == "shadow_ai_detected_outbound"
    assert event["selected_provider"] == "openai"
    assert event["detected_endpoint"] == "api.openai.com/v1/chat/completions"
    assert kwargs["detector_slug"] == "defense"


async def test_allowed_egress_passes_silently(monkeypatch):
    # Vector 12: egress to an allowed provider → no event (no false positive).
    from orchestration.context import HookContext

    emit = AsyncMock(return_value=True)
    monkeypatch.setattr(HookContext, "emit", emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("openai", "anthropic")))
    await egress_request_hook(httpx.Request("POST", "https://api.openai.com/v1/chat/completions"))
    emit.assert_not_called()


async def test_traffic_bypassing_sentinel_undetected(monkeypatch):
    # Vector 13 (HONEST LIMITATION, ADR-0010 §12.1): the hook is registered ONLY on
    # Sentinel's OpenAI + Anthropic httpx clients. Traffic that bypasses Sentinel
    # entirely (network-layer) or Bedrock egress via aioboto3 never invokes the hook,
    # so it is UNDETECTED. We do not claim otherwise.
    from orchestration.context import HookContext

    emit = AsyncMock(return_value=True)
    monkeypatch.setattr(HookContext, "emit", emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("anthropic",)))

    # (a) A bedrock host IS classifiable, but its egress goes via aioboto3 (no httpx
    #     hook) — i.e. the hook is never invoked for it. Not calling the hook models
    #     that bypass: no event is produced.
    assert resolve_provider("bedrock-runtime.us-east-1.amazonaws.com") == "bedrock"
    emit.assert_not_called()  # hook never ran for the aioboto3/bypass path

    # (b) Even if some non-Sentinel egress reached an unknown host, the monitor
    #     cannot classify it (out of scope) — no event.
    await egress_request_hook(httpx.Request("POST", "https://attacker-llm.example.com/v1/chat"))
    emit.assert_not_called()
