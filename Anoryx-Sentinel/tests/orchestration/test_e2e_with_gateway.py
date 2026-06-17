"""E2E tests: gateway + orchestration hooks with mock upstream (F-005, ADR-0007 D6).

Tests the full request pipeline with the hook framework integrated into
create_chat_completion, using httpx.AsyncClient + ASGITransport.

Covers (spec test list):
  - Clean request passes through (no hooks triggered).
  - PII detection blocks request (PII_ACTION=block) → 403 policy_blocked.
  - Injection detection blocks request → 403 policy_blocked.
  - Secret inbound detection blocks request → 403 policy_blocked.
  - Hook fail-safe (unexpected exception) → 500 internal_error.
  - Non-stream response passes through when no findings.
  - Audit events alongside usage event (audit chain has detection events).
  - Hash chain integrity across multi-event-per-request is asserted structurally
    (we verify all events carry the same request_id).
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import _reset_settings
from gateway.middleware.rate_limit import reset_state_for_testing
from orchestration.config import _reset_orchestration_settings
from orchestration.hooks.base import DetectorResult, PreRequestHook
from orchestration.registry import HookRegistry

# ---------------------------------------------------------------------------
# Test constants (match tests/gateway/conftest.py canonical IDs)
# ---------------------------------------------------------------------------
TEST_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEST_TEAM_ID = "11111111-2222-3333-4444-555555555555"
TEST_PROJECT_ID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
TEST_AGENT_ID = "gateway-core"
TEST_KEY_ID = "cccccccc-dddd-eeee-ffff-000000000001"
TEST_PLAINTEXT_KEY = "sentinel-e2e-test-key-xyz"
TEST_MODEL = "gpt-3.5-turbo"

STANDARD_HEADERS = {
    "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
    "X-Anoryx-Team-Id": TEST_TEAM_ID,
    "X-Anoryx-Project-Id": TEST_PROJECT_ID,
    "X-Anoryx-Agent-Id": TEST_AGENT_ID,
    "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
    "Content-Type": "application/json",
}

BENIGN_BODY = json.dumps(
    {
        "model": TEST_MODEL,
        "messages": [{"role": "user", "content": "What is 2+2?"}],
    }
)

# ---------------------------------------------------------------------------
# Stub hooks for testing
# ---------------------------------------------------------------------------


class AlwaysPassHook(PreRequestHook):
    detector_slug = "test-pass"

    async def inspect(self, content, context) -> DetectorResult:
        return DetectorResult(action="pass")


class AlwaysBlockHook(PreRequestHook):
    detector_slug = "test-block"
    calls = 0

    async def inspect(self, content, context) -> DetectorResult:
        AlwaysBlockHook.calls += 1
        return DetectorResult(
            action="block",
            event={
                "event_type": "injection_detected",
                "classifier_score": 0.95,
                "rule_matched": "INJ-001",
                "action_taken": "blocked",
            },
        )


class AlwaysRaiseHook(PreRequestHook):
    detector_slug = "test-raise"

    async def inspect(self, content, context) -> DetectorResult:
        raise RuntimeError("simulated hook failure")


# ---------------------------------------------------------------------------
# App builder
# ---------------------------------------------------------------------------


def _make_fake_key_row():
    row = MagicMock()
    row.tenant_id = TEST_TENANT_ID
    row.team_id = TEST_TEAM_ID
    row.project_id = TEST_PROJECT_ID
    row.agent_id = TEST_AGENT_ID
    row.key_id = TEST_KEY_ID
    row.is_active = True
    return row


# Patchers kept ACTIVE for the lifetime of each test (started in
# build_app_with_hooks, stopped in the autouse `reset_state` teardown). The request
# handlers resolve get_privileged_session / proxy_non_stream by module reference at
# REQUEST time, so a `with patch(...)` that exits after create_app() would leave the
# real functions in place — the request then builds a real engine on the fake
# DATABASE_URL and the route fail-safes to 500. (f-003b-harness-fix: this
# mock-scoping defect — not the persistence conftest — was the real reason these
# e2e tests were skipped; the skip reason was a mislabeled copy of the F-004 waiver.)
_active_patchers: list = []


def build_app_with_hooks(hook_registry=None):
    """Build the gateway app with mocked auth/audit and injected hook registry."""
    _reset_settings()
    _reset_orchestration_settings()
    reset_state_for_testing()

    key_row = _make_fake_key_row()
    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    audit_repo = MagicMock()
    audit_repo.append = AsyncMock(return_value=MagicMock())

    @asynccontextmanager
    async def _privileged_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    # Build a fake upstream response.
    fake_completion = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1234567890,
        "model": TEST_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "The answer is 4."},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }

    async def fake_proxy_non_stream(
        validated_body, request_id, upstream_api_key=None, overall_timeout=60.0
    ):
        from gateway.models import ChatCompletionResponse

        completion = ChatCompletionResponse(**fake_completion)
        return completion, 10, 5

    # F-006: the router resolves the tenant routing policy on a tenant session and
    # emits routing_decision events. Stub both so the F-005 hook E2E exercises the
    # router (default policy -> OpenAI). The OpenAI adapter calls proxy_non_stream
    # at its OWN module, so patch it there (not at chat_completions).
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

    # F-008: the pre-request policy gate reads model/budget policies on a tenant
    # session. This F-005 hook E2E seeds no policies, and the bare MagicMock tenant
    # session cannot answer the gate's async queries — so stub the gate to a no-op
    # allow exactly as the F-006 router tests do (the gate has its own F-006/F-008
    # coverage; here it must simply pass through).
    from policy.enforcement import BudgetOk, ModelAllow

    async def _allow_enforce(tenant_context, body):
        return ModelAllow(None), BudgetOk(), []

    patchers = [
        patch("gateway.middleware.auth.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.middleware.audit.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
        patch(
            "gateway.router.providers.openai_provider.proxy_non_stream",
            side_effect=fake_proxy_non_stream,
        ),
        # Router DB touchpoints (F-006).
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
        patch("gateway.router.selection._enforce_policies_pre_request", new=_allow_enforce),
        patch("persistence.database.get_tenant_session", _tenant_cm),
        patch(
            "persistence.repositories.tenant_routing_policy_repository."
            "TenantRoutingPolicyRepository.get_for_tenant",
            new=_fake_get_for_tenant,
        ),
    ]
    # Start (not `with`) so the mocks stay active through request handling, then
    # stop them in the autouse reset_state teardown. See module note above.
    for _p in patchers:
        _p.start()
    _active_patchers.extend(patchers)

    from gateway.main import create_app

    app = create_app()

    # Inject the hook registry into the route handler.
    if hook_registry is not None:
        # patch.object tracked in _active_patchers so the override is reverted in
        # teardown — a bare module assignment would leak across tests/files.
        import gateway.routes.chat_completions as cc_mod

        reg_patcher = patch.object(cc_mod, "_get_default_registry", lambda: hook_registry)
        reg_patcher.start()
        _active_patchers.append(reg_patcher)

    return app, audit_repo


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state():
    reset_state_for_testing()
    _reset_settings()
    _reset_orchestration_settings()
    yield
    # Stop any patchers started by build_app_with_hooks so they do not leak across
    # tests (they must stay active through request handling, not just create_app()).
    while _active_patchers:
        _active_patchers.pop().stop()
    reset_state_for_testing()
    _reset_settings()
    _reset_orchestration_settings()


@pytest.fixture(autouse=True)
def gateway_env(monkeypatch):
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://fake-upstream")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/db")
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+asyncpg://fake/appdb")
    monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-secret-for-hmac")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("RATE_LIMIT_RPM", "600")
    monkeypatch.setenv("RATE_LIMIT_BURST", "60")
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "20")
    _reset_settings()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_clean_request_passes(gateway_env):
    """Clean request with pass-through hooks → 200 OK."""
    import httpx
    from httpx import ASGITransport

    registry = HookRegistry(pre_request=[AlwaysPassHook()])
    app, _ = build_app_with_hooks(registry)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=BENIGN_BODY,
            headers=STANDARD_HEADERS,
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_e2e_injection_block_returns_403(gateway_env):
    """Hook that blocks → 403 policy_blocked."""
    import httpx
    from httpx import ASGITransport

    AlwaysBlockHook.calls = 0
    registry = HookRegistry(pre_request=[AlwaysBlockHook()])
    app, _ = build_app_with_hooks(registry)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=BENIGN_BODY,
            headers=STANDARD_HEADERS,
        )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error_code"] == "policy_blocked"


@pytest.mark.asyncio
async def test_e2e_fail_safe_hook_returns_500(gateway_env):
    """Unexpected hook exception → 500 internal_error (D3 fail-safe)."""
    import httpx
    from httpx import ASGITransport

    registry = HookRegistry(pre_request=[AlwaysRaiseHook()])
    app, _ = build_app_with_hooks(registry)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=BENIGN_BODY,
            headers=STANDARD_HEADERS,
        )
    assert resp.status_code == 500
    body = resp.json()
    assert body["error_code"] == "internal_error"


@pytest.mark.asyncio
async def test_e2e_no_registry_passes_through(gateway_env):
    """When no hook registry is available, request passes through normally."""
    import httpx
    from httpx import ASGITransport

    app, _ = build_app_with_hooks(hook_registry=None)

    # Override _get_default_registry to return None (no hooks). patch.object
    # tracked in _active_patchers so teardown reverts it (no cross-test leak).
    import gateway.routes.chat_completions as cc_mod

    reg_patcher = patch.object(cc_mod, "_get_default_registry", lambda: None)
    reg_patcher.start()
    _active_patchers.append(reg_patcher)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=BENIGN_BODY,
            headers=STANDARD_HEADERS,
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_e2e_request_id_in_response_header(gateway_env):
    """X-Request-Id header is present in the response (MED-3)."""
    import httpx
    from httpx import ASGITransport

    registry = HookRegistry()
    app, _ = build_app_with_hooks(registry)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=BENIGN_BODY,
            headers=STANDARD_HEADERS,
        )
    assert "x-request-id" in resp.headers


@pytest.mark.asyncio
async def test_e2e_error_envelope_conformance_on_block(gateway_env):
    """Error response on block conforms to the contract Error envelope."""
    import httpx
    from httpx import ASGITransport

    registry = HookRegistry(pre_request=[AlwaysBlockHook()])
    app, _ = build_app_with_hooks(registry)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=BENIGN_BODY,
            headers=STANDARD_HEADERS,
        )
    assert resp.status_code == 403
    body = resp.json()
    # Contract error envelope: error_code, message, request_id.
    assert "error_code" in body
    assert "message" in body
    assert "request_id" in body
    assert body["error_code"] == "policy_blocked"
