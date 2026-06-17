"""Shadow-AI egress monitor (F-007, ADR-0010 §5).

Unit tests for the httpx request event-hook + the outbound-emit primitive. No
network, no DB: the outbound emit and HookContext.emit are patched. These prove:
host→provider resolution; allowed egress is silent; disallowed egress emits
shadow_ai_detected_outbound; untracked hosts and an unbound context are no-ops;
the hook NEVER raises into the provider call (defense-in-depth); and the outbound
emit builds a sanitized, contract-shaped event.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from gateway.context import EgressContext, TenantContext, current_egress_context
from gateway.middleware import egress_monitor as em
from gateway.middleware.egress_monitor import egress_request_hook, resolve_provider

TC = TenantContext(
    tenant_id="t-1", team_id="tm-1", project_id="p-1", agent_id="a-1", virtual_key_id="k-1"
)
_EMIT_PATH = "orchestration.detectors.shadow_ai_detector.emit_shadow_ai_outbound_event"


@pytest.fixture(autouse=True)
def _clear_egress():
    yield
    current_egress_context.set(None)


def _req(url: str, method: str = "POST") -> httpx.Request:
    return httpx.Request(method, url)


# --------------------------------------------------------------------------- #
# host → provider resolution
# --------------------------------------------------------------------------- #


def test_resolve_provider_known_hosts():
    assert resolve_provider("api.openai.com") == "openai"
    assert resolve_provider("api.anthropic.com") == "anthropic"
    assert resolve_provider("bedrock-runtime.us-east-1.amazonaws.com") == "bedrock"
    assert resolve_provider("bedrock.us-west-2.amazonaws.com") == "bedrock"


def test_resolve_provider_untracked_or_empty():
    assert resolve_provider("example.com") is None
    assert resolve_provider("evil.amazonaws.com") is None  # not a bedrock host
    assert resolve_provider("") is None
    assert resolve_provider(None) is None


# --------------------------------------------------------------------------- #
# the event hook
# --------------------------------------------------------------------------- #


async def test_hook_noop_without_bound_context(monkeypatch):
    emit = AsyncMock()
    monkeypatch.setattr(_EMIT_PATH, emit)
    await egress_request_hook(_req("https://api.openai.com/v1/chat/completions"))
    emit.assert_not_called()  # no EgressContext bound → nothing to compare against


async def test_hook_silent_for_allowed_provider(monkeypatch):
    emit = AsyncMock()
    monkeypatch.setattr(_EMIT_PATH, emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("openai", "anthropic")))
    await egress_request_hook(_req("https://api.openai.com/v1/chat/completions"))
    emit.assert_not_called()


async def test_hook_flags_disallowed_provider_egress(monkeypatch):
    emit = AsyncMock()
    monkeypatch.setattr(_EMIT_PATH, emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("anthropic",)))  # openai NOT allowed
    await egress_request_hook(_req("https://api.openai.com/v1/chat/completions"))
    emit.assert_awaited_once()
    kw = emit.call_args.kwargs
    assert kw["provider"] == "openai"
    assert kw["endpoint"] == "api.openai.com/v1/chat/completions"
    assert kw["egress"].tenant_context is TC


async def test_hook_ignores_untracked_host(monkeypatch):
    emit = AsyncMock()
    monkeypatch.setattr(_EMIT_PATH, emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("anthropic",)))
    await egress_request_hook(_req("https://example.com/some/path"))
    emit.assert_not_called()  # not a tracked provider host → out of scope


async def test_hook_never_raises_into_provider_call(monkeypatch):
    emit = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(_EMIT_PATH, emit)
    current_egress_context.set(EgressContext(TC, "req-1", ("anthropic",)))
    # Must NOT raise — the monitor is defense-in-depth, never breaks the call.
    await egress_request_hook(_req("https://api.openai.com/v1/chat/completions"))


# --------------------------------------------------------------------------- #
# the outbound-emit primitive (shadow_ai_detected_outbound)
# --------------------------------------------------------------------------- #


async def test_outbound_emit_builds_sanitized_event(monkeypatch):
    from orchestration.context import HookContext
    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_outbound_event

    emit = AsyncMock(return_value=True)
    monkeypatch.setattr(HookContext, "emit", emit)
    egress = EgressContext(TC, "req-1", ("anthropic",))
    ok = await emit_shadow_ai_outbound_event(
        egress=egress, provider="openai", endpoint="api.openai.com/v1/chat?key=secret#frag"
    )
    assert ok is True
    ev = emit.call_args[0][0]
    assert ev["event_type"] == "shadow_ai_detected_outbound"
    assert ev["selected_provider"] == "openai"
    assert ev["action_taken"] == "logged"
    # query/fragment stripped (D7) — no secret leaks into the endpoint.
    assert "?" not in ev["detected_endpoint"] and "#" not in ev["detected_endpoint"]
    assert "secret" not in ev["detected_endpoint"]


async def test_outbound_emit_rejects_invalid_endpoint(monkeypatch):
    from orchestration.context import HookContext
    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_outbound_event

    emit = AsyncMock(return_value=True)
    monkeypatch.setattr(HookContext, "emit", emit)
    egress = EgressContext(TC, "req-1", ())
    ok = await emit_shadow_ai_outbound_event(egress=egress, provider="openai", endpoint="")
    assert ok is False
    emit.assert_not_called()


# --------------------------------------------------------------------------- #
# binding the per-request egress context
# --------------------------------------------------------------------------- #


async def test_bind_egress_context_sets_contextvar(monkeypatch):
    monkeypatch.setattr(
        em, "_resolve_allowed_providers", AsyncMock(return_value=["openai", "anthropic"])
    )
    await em.bind_egress_context(TC, "req-9")
    eg = current_egress_context.get()
    assert eg is not None
    assert eg.request_id == "req-9"
    assert eg.allowed_providers == ("openai", "anthropic")
    assert eg.tenant_context is TC


async def test_resolve_allowed_providers_reads_tenant_policy(monkeypatch):
    @asynccontextmanager
    async def _fake_session(*_a, **_k):
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    fake_repo = MagicMock()
    fake_repo.get_for_tenant = AsyncMock(return_value=MagicMock(allowed_providers=["openai"]))
    monkeypatch.setattr("persistence.database.get_tenant_session", _fake_session)
    monkeypatch.setattr(
        "persistence.repositories.tenant_routing_policy_repository.TenantRoutingPolicyRepository",
        lambda session: fake_repo,
    )
    out = await em._resolve_allowed_providers(TC)
    assert out == ["openai"]
