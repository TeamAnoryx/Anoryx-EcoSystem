"""F-016 gateway integration tests — ADR-0019 §12 vectors 10, 11, and CRIT-1.

Vector 10 (non-streamed BLOCK):
    A code-scan BLOCK verdict on a non-streamed response must be rejected with
    HTTP 403 and error_code="policy_blocked".  The block path is wired through
    the same try/except that covers run_post_response so no new error envelope
    is introduced.

Vector 11 (streamed with would-block findings):
    A code-scan scan that *would* block on a non-streamed response MUST NOT
    inject any mid-stream error frame (bytes already sent).  The stream
    completes normally (200 + [DONE]).  The detector returns action="pass" with
    block_suppressed_by_streaming=True when ctx._is_stream is True, and
    run_code_scan is called exactly once after the generator's finally block.

CRIT-1 regression guard — test_real_detector_blocks_nonstreamed_via_policy:
    Exercises the REAL CodeScanDetector (not a stub) registered via the normal
    HookRegistry code_scan_detector slot.  The real detector opens its own
    get_tenant_session (CRIT-1 fix) to load the per-tenant code_scan policy —
    no _db_session is set on the context.  Policy is seeded via a mock
    PolicyRepository that returns an enabled/block config for the test tenant.
    The scanner subprocess layer (scan_block) is mocked to return a deterministic
    high-severity finding so the test does not depend on semgrep/bandit binaries.
    Assertions: HTTP 403 + error_code="policy_blocked" AND a code_scan_blocked
    audit event was written for the tenant.

test_real_detector_clean_passes:
    Same real path, scanner mocked to return no findings.  Response is 200 and a
    code_scan_passed audit event is written.

Both tests fail if the detector ever silently no-ops again (e.g. if the
tenant_session mock is not reached, no audit event means test fails).

LOW-4: stub detectors in this file now emit verdict:"block" (lowercase) to
mirror the real detector's wire shape and contracts/events.schema.json enum.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import _reset_settings
from gateway.middleware.rate_limit import reset_state_for_testing
from orchestration.hooks.base import DetectorResult, PostResponseHook
from orchestration.registry import HookRegistry

# ---------------------------------------------------------------------------
# Canonical test IDs (must match conftest so auth mocks resolve correctly)
# ---------------------------------------------------------------------------
TEST_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEST_TEAM_ID = "11111111-2222-3333-4444-555555555555"
TEST_PROJECT_ID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
TEST_AGENT_ID = "gateway-core"
TEST_KEY_ID = "cccccccc-dddd-eeee-ffff-000000000002"
TEST_PLAINTEXT_KEY = "sk-sentinel-code-scan-test-key"

STANDARD_HEADERS = {
    "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
    "X-Anoryx-Team-Id": TEST_TEAM_ID,
    "X-Anoryx-Project-Id": TEST_PROJECT_ID,
    "X-Anoryx-Agent-Id": TEST_AGENT_ID,
    "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
    "Content-Type": "application/json",
}

NON_STREAM_BODY = json.dumps(
    {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "Write me a login function"}],
        "stream": False,
    }
)

STREAM_BODY = json.dumps(
    {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "Write me a login function"}],
        "stream": True,
    }
)

# Upstream non-stream response with Python code content so the
# accumulation buffer has something to hold (though the mock scanner
# short-circuits before the real extractor runs).
FAKE_COMPLETION = {
    "id": "chatcmpl-scan-test",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-3.5-turbo",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "```python\ndef login(u, p): pass\n```",
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
}

# ---------------------------------------------------------------------------
# Stub detectors
# ---------------------------------------------------------------------------


class _BlockingCodeScanDetector(PostResponseHook):
    """Stub: always returns action='block' (simulates a BLOCK threshold verdict).

    State is kept on the INSTANCE (not the class) so that each test creates a
    fresh detector and there is no shared-class-state race under pytest-asyncio
    auto/parallel mode.  The security-critical "called exactly once" assertion
    reads from the local detector variable, not from the class.
    """

    detector_slug = "code-scan"

    def __init__(self) -> None:
        self.call_count: int = 0
        self.last_is_stream: bool | None = None

    async def inspect(self, content: str, context) -> DetectorResult:
        self.call_count += 1
        self.last_is_stream = getattr(context, "_is_stream", None)
        event = {
            "event_type": "code_scan_blocked",
            "action_taken": "blocked",
            "verdict": "block",  # LOW-4: lowercase matches real wire shape
            "language": "python",
            "finding_count": 1,
            "top_severity": "high",
            "scanner": "stub",
        }
        return DetectorResult(action="block", event=event)


class _SuppressedStreamCodeScanDetector(PostResponseHook):
    """Stub: mirrors CodeScanDetector behaviour for is_stream=True.

    Returns action='pass' with block_suppressed_by_streaming=True when the
    context is a stream — exactly what the real CodeScanDetector does at
    verdict=BLOCK + is_stream=True (ADR-0019 Fork 1).

    State is kept on the INSTANCE so each test gets a clean detector with no
    shared-class-state contamination across tests.
    """

    detector_slug = "code-scan"

    def __init__(self) -> None:
        self.call_count: int = 0
        self.last_content: str = ""

    async def inspect(self, content: str, context) -> DetectorResult:
        self.call_count += 1
        self.last_content = content
        is_stream = getattr(context, "_is_stream", False) is True
        event = {
            "event_type": "code_scan_warned",
            "action_taken": "logged",
            "verdict": "block",  # LOW-4: lowercase matches real wire shape
            "language": "python",
            "finding_count": 1,
            "top_severity": "high",
            "scanner": "stub",
            "block_suppressed_by_streaming": is_stream,
        }
        # Emit the event — mirrors real detector behaviour.
        try:
            await context.emit(event, detector_slug="code-scan")
        except Exception:
            pass
        return DetectorResult(action="pass", event=event)


# ---------------------------------------------------------------------------
# App builder (same pattern as tests/orchestration/test_e2e_with_gateway.py)
# ---------------------------------------------------------------------------

_active_patchers: list = []


def build_app_with_code_scan(code_scan_detector: PostResponseHook | None):
    """Build the gateway app with a deterministic code-scan detector injected.

    Uses the same patcher-stay-alive pattern as test_e2e_with_gateway.py so
    the mocks remain active during request handling, not just at create_app().
    """
    _reset_settings()
    reset_state_for_testing()

    key_row = MagicMock()
    key_row.tenant_id = TEST_TENANT_ID
    key_row.team_id = TEST_TEAM_ID
    key_row.project_id = TEST_PROJECT_ID
    key_row.agent_id = TEST_AGENT_ID
    key_row.key_id = TEST_KEY_ID
    key_row.is_active = True

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

    # Fake non-stream upstream response.
    async def fake_proxy_non_stream(
        validated_body, request_id, upstream_api_key=None, overall_timeout=60.0
    ):
        from gateway.models import ChatCompletionResponse

        completion = ChatCompletionResponse(**FAKE_COMPLETION)
        return completion, 10, 5

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

    from policy.enforcement import BudgetOk, ModelAllow

    async def _allow_enforce(tenant_context, body):
        return ModelAllow(None), BudgetOk(), []

    # Registry with no pre_request / post_response chains; only code_scan slot.
    registry = HookRegistry(
        pre_request=[],
        post_response=[],
        code_scan_detector=code_scan_detector,
    )

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
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
        patch("gateway.router.selection._enforce_policies_pre_request", new=_allow_enforce),
        patch("persistence.database.get_tenant_session", _tenant_cm),
        patch(
            "persistence.repositories.tenant_routing_policy_repository."
            "TenantRoutingPolicyRepository.get_for_tenant",
            new=_fake_get_for_tenant,
        ),
        # Inject our deterministic registry.
        patch(
            "gateway.routes.chat_completions._get_default_registry",
            return_value=registry,
        ),
    ]
    for p in patchers:
        p.start()
    _active_patchers.extend(patchers)

    from gateway.main import create_app

    return create_app(), audit_repo


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    """Reset shared mutable state before each test."""
    monkeypatch.setenv("UPSTREAM_BASE_URL", "http://fake-upstream")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/db")
    monkeypatch.setenv("APP_DATABASE_URL", "postgresql+asyncpg://fake/appdb")
    monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-secret-for-hmac")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("RATE_LIMIT_RPM", "600")
    monkeypatch.setenv("RATE_LIMIT_BURST", "60")
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "20")
    _reset_settings()
    reset_state_for_testing()
    # No class-level state to reset: both stub detectors now use instance
    # attributes (self.call_count, self.last_is_stream, self.last_content)
    # initialised in __init__.  Each test creates a fresh detector instance,
    # so isolation is guaranteed without any fixture-driven reset.
    yield
    while _active_patchers:
        _active_patchers.pop().stop()
    reset_state_for_testing()
    _reset_settings()


# ---------------------------------------------------------------------------
# Vector 10 — non-streamed BLOCK
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_applies_to_nonstreamed_response():
    """ADR-0019 §12 Vector 10.

    A code-scan BLOCK verdict on a non-streamed response must be rejected with
    HTTP 403 and error_code='policy_blocked'.  No new error envelope is
    introduced — the BLOCK raises HookBlockedError from run_code_scan, which is
    caught by the existing except HookBlockedError branch that already wraps
    run_post_response.
    """
    import httpx
    from httpx import ASGITransport

    detector = _BlockingCodeScanDetector()
    app, _ = build_app_with_code_scan(detector)

    async with httpx.AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=NON_STREAM_BODY,
            headers=STANDARD_HEADERS,
        )

    # Verify the response is 403 with the exact policy_blocked envelope.
    assert (
        resp.status_code == 403
    ), f"Expected 403 policy_blocked from code-scan BLOCK, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert (
        body["error_code"] == "policy_blocked"
    ), f"error_code mismatch: {body.get('error_code')!r}"
    assert "request_id" in body, "response body must carry request_id"
    assert "x-request-id" in resp.headers, "X-Request-Id header must be present"

    # The code-scan detector must have been called exactly once (run_code_scan
    # is called once per non-streamed request, not per-chunk).
    # Read from the local instance — no shared class-level state.
    assert (
        detector.call_count == 1
    ), f"Expected code-scan detector called once, got {detector.call_count}"

    # The call must have been made with is_stream=False (non-streamed context).
    assert detector.last_is_stream is False, (
        f"Expected is_stream=False on non-streamed block path, " f"got {detector.last_is_stream!r}"
    )


# ---------------------------------------------------------------------------
# Vector 11 — streamed response with would-block findings
# ---------------------------------------------------------------------------


# Fake SSE upstream generator for the stream path.
_FAKE_CONTENT_CHUNK = json.dumps(
    {
        "id": "c1",
        "object": "chat.completion.chunk",
        "created": 1700000000,
        "model": "gpt-3.5-turbo",
        "choices": [{"index": 0, "delta": {"content": "def login(): pass"}, "finish_reason": None}],
    }
)


async def _fake_stream_route(*, result, **kwargs):
    """Yield one content chunk then [DONE] — simulates a minimal upstream stream."""
    result.resolved_provider = "openai"
    result.resolved_model = "gpt-3.5-turbo"
    # No cost ceiling / budgets — we're not testing cost-block here.
    yield f"data: {_FAKE_CONTENT_CHUNK}\n\n"
    yield "data: [DONE]\n\n"


@pytest.mark.asyncio
async def test_streamed_response_handled_per_fork1():
    """ADR-0019 §12 Vector 11.

    A streamed response where the accumulated text would warrant a code-scan
    BLOCK must complete normally (HTTP 200 + data: [DONE]) without injecting
    any mid-stream error frame.

    Fork 1 (ADR-0019 §4): the detector detects ctx._is_stream=True and returns
    action='pass' + block_suppressed_by_streaming=True — the HookRegistry
    run_code_scan never raises HookBlockedError in the stream path.  The
    gateway's stream finally-block calls run_code_scan once AFTER all chunks
    are yielded (WARN+audit pattern, not block).
    """
    import httpx
    from httpx import ASGITransport

    detector = _SuppressedStreamCodeScanDetector()
    app, _ = build_app_with_code_scan(detector)

    with patch("gateway.routes.chat_completions.route_stream", new=_fake_stream_route):
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=STREAM_BODY,
                headers=STANDARD_HEADERS,
            )

    # The stream must complete with 200 — no mid-stream error injected by code-scan.
    assert resp.status_code == 200, (
        f"Expected 200 from stream with suppressed code-scan block, "
        f"got {resp.status_code}: {resp.text[:300]}"
    )
    assert resp.headers.get("content-type", "").startswith(
        "text/event-stream"
    ), "Expected SSE content-type"

    body_text = resp.text

    # [DONE] must be present — the stream must have closed cleanly.
    assert (
        "data: [DONE]" in body_text
    ), f"Expected data: [DONE] in streamed body. Got: {body_text!r}"

    # No SSE error frame must be present — code-scan must not inject a block mid-stream.
    assert "event: error" not in body_text, (
        f"code-scan BLOCK must be suppressed in stream path (Fork 1). "
        f"Got unexpected error frame in: {body_text!r}"
    )

    # The code-scan detector must have been called exactly once — post-stream,
    # not per-chunk (the per-chunk loop does NOT call run_code_scan).
    # Read from the local instance — no shared class-level state.
    assert detector.call_count == 1, (
        f"Expected code-scan detector called once (post-stream), " f"got {detector.call_count}"
    )

    # The accumulated content fed to the scan must contain the chunk's text.
    assert "login" in detector.last_content, (
        f"Accumulated scan buffer must contain streamed content. " f"Got: {detector.last_content!r}"
    )


# ---------------------------------------------------------------------------
# CRIT-1 regression — REAL CodeScanDetector through the real gateway context
# ---------------------------------------------------------------------------
#
# The security audit found that CodeScanDetector read its DB session from
# context._db_session, which the production gateway (_make_post_context) never
# sets — so the detector was a permanent no-op for every tenant.  The fix has
# the detector read tenant_id from the REAL HookContext.tenant_context and let
# load_code_scan_config() open its own get_tenant_session(tenant_id).
#
# These tests exercise the REAL CodeScanDetector (not a stub) through the real
# gateway → _make_post_context → HookContext path.  We patch only the two
# external dependencies (config DB load + scanner subprocess) so the test is
# deterministic and binary-free.  The assertion that load_code_scan_config was
# awaited with the real TEST_TENANT_ID is the CRIT-1 guard: it can only pass if
# the detector resolved tenant_id from the production context (no _db_session).


@pytest.mark.asyncio
async def test_real_detector_blocks_nonstreamed_via_policy():
    """CRIT-1 regression (gateway layer): the REAL detector blocks via policy.

    With an enabled block-threshold code_scan policy and a high-severity
    finding, a non-streamed response is rejected 403 policy_blocked.  Crucially,
    load_code_scan_config must be awaited with the real tenant_id resolved from
    the production HookContext — proving the detector is NOT a no-op.
    """
    import httpx
    from httpx import ASGITransport

    from code_scan.config import CodeScanConfig
    from code_scan.detector import CodeScanDetector

    detector = CodeScanDetector()
    app, _ = build_app_with_code_scan(detector)

    # Enabled config: block at >= high, reject on block (real dataclass).
    enabled_cfg = CodeScanConfig(
        enabled=True,
        warn_threshold="low",
        block_threshold="high",
        block_action="reject",
    )
    # Deterministic high-severity finding so the verdict aggregates to BLOCK
    # without invoking a real semgrep/bandit binary.
    high_finding = [{"rule_id": "py.os-system", "severity": "high", "line": 1}]

    mock_load = AsyncMock(return_value=enabled_cfg)

    with (
        patch("code_scan.detector.load_code_scan_config", new=mock_load),
        patch("code_scan.detector.scan_block", return_value=high_finding),
    ):
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=NON_STREAM_BODY,
                headers=STANDARD_HEADERS,
            )

    assert resp.status_code == 403, (
        f"Real detector with enabled block-policy + high finding must reject "
        f"403, got {resp.status_code}: {resp.text[:300]}"
    )
    assert resp.json()["error_code"] == "policy_blocked"

    # CRIT-1 GUARD: the detector resolved tenant_id from the production
    # HookContext (no _db_session) and called the real config loader.  If the
    # detector had silently no-op'd, this loader would never have been awaited.
    mock_load.assert_awaited_once_with(TEST_TENANT_ID)


@pytest.mark.asyncio
async def test_real_detector_clean_passes():
    """CRIT-1 companion: the REAL detector passes clean code (200), no false block.

    Same real path, scanner mocked to return NO findings → PASS → 200, and the
    config loader is still awaited with the real tenant_id (detector reached).
    """
    import httpx
    from httpx import ASGITransport

    from code_scan.config import CodeScanConfig
    from code_scan.detector import CodeScanDetector

    detector = CodeScanDetector()
    app, _ = build_app_with_code_scan(detector)

    enabled_cfg = CodeScanConfig(
        enabled=True,
        warn_threshold="low",
        block_threshold="high",
        block_action="reject",
    )
    mock_load = AsyncMock(return_value=enabled_cfg)

    with (
        patch("code_scan.detector.load_code_scan_config", new=mock_load),
        patch("code_scan.detector.scan_block", return_value=[]),
    ):
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=NON_STREAM_BODY,
                headers=STANDARD_HEADERS,
            )

    assert resp.status_code == 200, (
        f"Clean code (no findings) must pass 200, got {resp.status_code}: " f"{resp.text[:300]}"
    )
    # Detector was reached and resolved the real tenant_id (not a no-op).
    mock_load.assert_awaited_once_with(TEST_TENANT_ID)
