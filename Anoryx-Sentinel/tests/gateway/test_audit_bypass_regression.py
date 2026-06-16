"""Regression tests proving the audit bypass is dead (HIGH-1 fix) and
related security rework fixes (HIGH-2, MED-1, MED-2, MED-3).

HIGH-1 REGRESSION PROOF:
  These tests do NOT mock out emit_terminal_record at the route level.
  They assert that AuditLogRepository.append is called for EACH middleware-stage
  rejection:
  - 401 invalid_api_key (missing/bad Bearer key)
  - 400 missing_required_header (missing Sentinel ID header)
  - 413 request_too_large (oversized body)
  - 400 invalid_request (TE + CL smuggling signal)
  - 500 internal_error path (DB error during auth)

HIGH-2 REGRESSION:
  - OPTIONS /v1/chat/completions with an allowed Origin returns CORS headers,
    not 400 missing_required_header.

MED-1 REGRESSION:
  - Concurrent stream requests beyond the cap get 429, proving atomic admission.

MED-2 REGRESSION:
  - Idle gap > STREAM_TIMEOUT_SECONDS → error frame emitted.
  - Total runtime > REQUEST_TIMEOUT_SECONDS → error frame emitted.

MED-3 REGRESSION:
  - All error responses share the same canonical request_id (set by the
    outermost TerminalAuditMiddleware, not per-middleware).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.config import _reset_settings
from gateway.middleware.rate_limit import _stream_counters
from persistence.repositories.virtual_api_key_repository import VirtualApiKeyAuthError
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
    return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]}


def _make_audit_context(audit_repo_mock=None):
    """Return (audit_repo_mock, patches_list) where patches must stay active during requests.

    The patches target:
    - gateway.middleware.audit.get_privileged_session  — so emit_terminal_record
      gets a mock session for AuditLogRepository
    - gateway.middleware.audit.AuditLogRepository     — so append is intercepted

    The audit middleware is NOT patched at the route level, so the full
    emit_terminal_record path (including TerminalAuditMiddleware) is exercised.
    """
    if audit_repo_mock is None:
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = AsyncMock(return_value=MagicMock())

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    patches = [
        patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
        patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock),
    ]
    return audit_repo_mock, patches


def _make_auth_context(key_row=None, lookup_side_effect=None):
    """Return patches list for the auth layer (keep active during requests)."""
    if key_row is None:
        key_row = make_fake_key_row()

    auth_repo = MagicMock()
    if lookup_side_effect:
        auth_repo.lookup_by_plaintext = AsyncMock(side_effect=lookup_side_effect)
    else:
        auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    @asynccontextmanager
    async def _priv_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    return [
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
    ]


def _create_app():
    """Create the gateway app with settings reset."""
    _reset_settings()
    from gateway.main import create_app

    return create_app()


# ---------------------------------------------------------------------------
# HIGH-1: Audit fires for 401 (missing Bearer) — pre-auth rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_fires_for_401_missing_bearer(settings_env):
    """Audit row must be appended for 401 (missing Authorization header).

    Previously: TerminalAuditMiddleware did not exist; auth middleware returned
    JSONResponse directly, bypassing any audit. This test proves the bypass is dead.
    """
    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                # No Authorization header — triggers 401 from AuthMiddleware
                headers={
                    "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
                    "X-Anoryx-Team-Id": TEST_TEAM_ID,
                    "X-Anoryx-Project-Id": TEST_PROJECT_ID,
                    "X-Anoryx-Agent-Id": TEST_AGENT_ID,
                    "Content-Type": "application/json",
                },
                json=_valid_body(),
            )

    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_api_key"

    # KEY ASSERTION: audit was appended despite the rejection happening in middleware.
    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"
    # Pre-auth rejection: sentinel IDs (all-zeros tenant, gateway-core agent).
    assert event["tenant_id"] == "00000000-0000-0000-0000-000000000000"
    assert event["agent_id"] == "gateway-core"
    assert event["tokens_in"] == 0
    assert event["tokens_out"] == 0


@pytest.mark.asyncio
async def test_audit_fires_for_401_invalid_key(settings_env):
    """Audit row appended for 401 (VirtualApiKeyAuthError — revoked/invalid key)."""
    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context(lookup_side_effect=VirtualApiKeyAuthError("revoked"))

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json=_valid_body(),
            )

    assert resp.status_code == 401
    # Audit must have fired even though auth middleware returned JSONResponse directly.
    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"
    assert event["tenant_id"] == "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# HIGH-1: Audit fires for 400 (missing required header) — TenantContext rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_fires_for_400_missing_header(settings_env):
    """Audit row appended for 400 (missing X-Anoryx-Tenant-Id header).

    TenantContextMiddleware returns JSONResponse directly. Previously no audit
    fired. TerminalAuditMiddleware now catches this via send-wrapping.
    """
    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                # Intentionally omit X-Anoryx-Tenant-Id
                headers={
                    "X-Anoryx-Team-Id": TEST_TEAM_ID,
                    "X-Anoryx-Project-Id": TEST_PROJECT_ID,
                    "X-Anoryx-Agent-Id": TEST_AGENT_ID,
                    "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
                    "Content-Type": "application/json",
                },
                json=_valid_body(),
            )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "missing_required_header"

    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"
    assert event["tenant_id"] == "00000000-0000-0000-0000-000000000000"


@pytest.mark.asyncio
async def test_audit_fires_for_400_malformed_header(settings_env):
    """Audit row appended for 400 (malformed UUID in X-Anoryx-Tenant-Id)."""
    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(**{"X-Anoryx-Tenant-Id": "not-a-uuid"}),
                json=_valid_body(),
            )

    assert resp.status_code == 400
    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"


# ---------------------------------------------------------------------------
# HIGH-1: Audit fires for 413 (body too large) — RequestValidation rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_fires_for_413_oversize_body(settings_env, monkeypatch):
    """Audit row appended for 413 (body exceeds MAX_BODY_BYTES).

    RequestValidationMiddleware returns JSONResponse directly. Previously no
    audit fired. TerminalAuditMiddleware now covers this.
    """
    monkeypatch.setenv("MAX_BODY_BYTES", "50")
    _reset_settings()

    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=b"x" * 200,  # Exceeds 50-byte limit
                headers=_valid_headers(),
            )

    assert resp.status_code == 413
    assert resp.json()["error_code"] == "request_too_large"

    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"
    assert event["tokens_in"] == 0


# ---------------------------------------------------------------------------
# HIGH-1: Audit fires for 400 (TE + CL smuggling signal)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_fires_for_400_te_cl_conflict(settings_env):
    """Audit row appended for 400 (Transfer-Encoding + Content-Length conflict).

    This is a request-smuggling signal rejected by RequestValidationMiddleware.
    """
    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        body_bytes = b'{"model":"m","messages":[{"role":"user","content":"hi"}]}'
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=body_bytes,
                headers={
                    **_valid_headers(),
                    "Transfer-Encoding": "chunked",
                    "Content-Length": str(len(body_bytes)),
                },
            )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"

    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"


# ---------------------------------------------------------------------------
# MED-3: Single canonical request_id across all error responses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_canonical_request_id_on_401(settings_env):
    """A single canonical request_id is generated by the outermost wrapper.

    The request_id in the response body and X-Request-Id header must match,
    and must conform to the events.schema.json pattern ^[A-Za-z0-9._-]{1,64}$.
    """
    import re

    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers={
                    "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
                    "X-Anoryx-Team-Id": TEST_TEAM_ID,
                    "X-Anoryx-Project-Id": TEST_PROJECT_ID,
                    "X-Anoryx-Agent-Id": TEST_AGENT_ID,
                    "Content-Type": "application/json",
                    # No Authorization — triggers 401
                },
                json=_valid_body(),
            )

    assert resp.status_code == 401
    body = resp.json()
    rid_body = body["request_id"]
    rid_header = resp.headers.get("x-request-id")

    # Both must be present and equal.
    assert rid_body, "request_id missing from response body"
    assert rid_header, "X-Request-Id missing from response headers"
    assert rid_body == rid_header, "Body and header request_id must match"

    # Must conform to events.schema.json pattern.
    _PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
    assert _PATTERN.match(rid_body), f"request_id {rid_body!r} does not match schema pattern"

    # The request_id recorded in the audit event must match the response.
    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["request_id"] == rid_body, "Audit event request_id must match response request_id"


# ---------------------------------------------------------------------------
# HIGH-1 (500 path): Audit fires for 500 (generic DB error during auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_fires_for_500_db_error_during_auth(settings_env):
    """Audit row appended for 500 internal_error when auth DB lookup raises Exception.

    AuthMiddleware's `except Exception` branch (not VirtualApiKeyAuthError)
    returns _error_json("internal_error", ...) → status 500.
    TerminalAuditMiddleware must observe this via send-wrapping and emit the
    audit record with the same canonical request_id as the response.

    Proven without mocking emit_terminal_record — the full emit path runs.
    """
    audit_repo, audit_patches = _make_audit_context()

    # Patch get_privileged_session for auth to raise a generic Exception
    # (simulating DB connection failure — NOT VirtualApiKeyAuthError).
    @asynccontextmanager
    async def _failing_priv_cm():
        raise RuntimeError("simulated DB connection failure")
        yield  # pragma: no cover — needed to satisfy asynccontextmanager

    auth_patches = [
        patch("gateway.middleware.auth.get_privileged_session", _failing_priv_cm),
    ]

    with auth_patches[0], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                headers=_valid_headers(),
                json=_valid_body(),
            )

    assert resp.status_code == 500
    body = resp.json()
    assert body["error_code"] == "internal_error"

    # KEY ASSERTION: audit was appended even though auth raised an unexpected Exception.
    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert event["event_type"] == "usage"
    # Pre-auth rejection: sentinel IDs (all-zeros tenant, gateway-core agent).
    assert event["tenant_id"] == "00000000-0000-0000-0000-000000000000"
    assert event["agent_id"] == "gateway-core"
    assert event["tokens_in"] == 0
    assert event["tokens_out"] == 0
    # Canonical request_id must match the response body.
    assert (
        event["request_id"] == body["request_id"]
    ), "Audit event request_id must match the 500 response request_id"


# ---------------------------------------------------------------------------
# HIGH-2: CORS preflight resolves correctly (OPTIONS returns CORS headers, not 400)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cors_preflight_resolves_without_400(settings_env, monkeypatch):
    """OPTIONS /v1/chat/completions with an allowed Origin returns CORS headers, not 400.

    Previously CORSMiddleware was innermost (LIFO bug), so OPTIONS hit
    TenantContextMiddleware first → 400 missing_required_header.
    After HIGH-2 fix, CORS is outer to TenantContext so preflight resolves.

    Audit assertion: TerminalAuditMiddleware is outermost (wraps CORS's send
    callable). The CORS 200/204 preflight response is NOT text/event-stream, so
    is_sse stays False and the wrapper emits an audit record for the OPTIONS
    response. This proves the outermost wrapper observes CORS-handled responses.
    """
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", '["https://example.com"]')
    _reset_settings()

    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.options(
                "/v1/chat/completions",
                headers={
                    "Origin": "https://example.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization, Content-Type",
                },
            )

    # Must NOT be 400 (which would indicate TenantContext ran before CORS).
    assert (
        resp.status_code != 400
    ), f"OPTIONS preflight returned {resp.status_code} — CORS middleware is still innermost"
    # CORS response should be 200 or 204.
    assert resp.status_code in (200, 204), f"Unexpected status: {resp.status_code}"
    # CORS headers must be present.
    assert (
        "access-control-allow-origin" in resp.headers
        or "access-control-allow-methods" in resp.headers
    ), "CORS response headers missing from OPTIONS preflight"

    # Audit assertion: TerminalAuditMiddleware is outer to CORSMiddleware and
    # wraps its send callable. The CORS preflight response is not SSE, so the
    # wrapper emits an audit record. This proves the outermost wrapper observes
    # CORS-handled responses (not just security-middleware rejections).
    audit_repo.append.assert_awaited_once()


# ---------------------------------------------------------------------------
# MED-1: Atomic concurrent-stream cap enforcement (TOCTOU fix)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_atomic_stream_cap_rejects_over_cap(settings_env, monkeypatch):
    """Concurrent stream requests beyond cap=2 get 429 on the (cap+1)th request.

    MED-1 TOCTOU fix: check_rate_limit() now atomically increments the stream
    counter at admission. Previously only check_rate_limit() READ the counter and
    stream_slot() incremented later, so concurrent requests could all pass.
    """
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "2")
    monkeypatch.setenv("RATE_LIMIT_RPM", "600")
    monkeypatch.setenv("RATE_LIMIT_BURST", "600")
    _reset_settings()

    from gateway.exceptions import GatewayError
    from gateway.middleware.rate_limit import check_rate_limit

    key_id = "atomic-cap-test-key"
    tenant_id = "atomic-cap-test-tenant"

    # Admit first two stream requests — should succeed and atomically increment.
    await check_rate_limit(key_id, tenant_id, is_stream=True)
    await check_rate_limit(key_id + "-2", tenant_id, is_stream=True)

    # Counter must be 2 now (atomically incremented).
    assert (
        _stream_counters.get(tenant_id, 0) == 2
    ), f"Expected stream counter=2, got {_stream_counters.get(tenant_id, 0)}"

    # Third request must be rejected with 429.
    with pytest.raises(GatewayError) as exc_info:
        await check_rate_limit(key_id + "-3", tenant_id, is_stream=True)

    assert exc_info.value.error_code == "rate_limit_exceeded"
    assert exc_info.value.retry_after is not None

    # Counter must still be 2 (rejected request did not increment).
    assert _stream_counters.get(tenant_id, 0) == 2


@pytest.mark.asyncio
async def test_stream_slot_only_decrements(settings_env):
    """stream_slot() only decrements — it no longer increments (MED-1 fix).

    After MED-1: stream_slot() assumes check_rate_limit() already incremented.
    Entering stream_slot() must not increase the counter.
    """
    from gateway.middleware.rate_limit import stream_slot

    tenant = "slot-decrement-only-test"
    _stream_counters.pop(tenant, None)

    # Manually set counter to 1 (simulating what check_rate_limit would set).
    _stream_counters[tenant] = 1

    async with stream_slot(tenant):
        # Counter should still be 1 (not incremented to 2 by stream_slot entry).
        assert (
            _stream_counters.get(tenant, 0) == 1
        ), "stream_slot() must not increment counter (MED-1: check_rate_limit already did)"

    # After exit, counter decremented to 0 and pruned (LOW-1).
    assert _stream_counters.get(tenant, 0) == 0


# ---------------------------------------------------------------------------
# LOW-1: Pruning of zero-counter stream entries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_counter_pruned_on_zero(settings_env):
    """LOW-1: stream counter dict entry is removed when count reaches 0."""
    from gateway.middleware.rate_limit import stream_slot

    tenant = "prune-test-tenant"
    _stream_counters.pop(tenant, None)

    # Simulate check_rate_limit having incremented.
    _stream_counters[tenant] = 1

    async with stream_slot(tenant):
        pass  # exits normally

    # Entry should be gone, not left as {tenant: 0}.
    assert tenant not in _stream_counters, "Zero stream counter entry was not pruned (LOW-1)"


# ---------------------------------------------------------------------------
# MED-2: Idle timeout enforced per-chunk in _proxy_stream_generator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_idle_timeout_emits_error_frame(settings_env):
    """Idle gap > idle_timeout → error frame emitted, no [DONE].

    MED-2 fix: asyncio.wait_for(anext(...), idle_timeout) now enforces the
    idle gap. Previously idle_timeout was accepted but never used.
    """
    from gateway.models import CreateChatCompletionRequest
    from gateway.upstream.openai_proxy import _proxy_stream_generator

    def _make_request() -> CreateChatCompletionRequest:
        return CreateChatCompletionRequest(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
        )

    mock_response = MagicMock()
    mock_response.status_code = 200

    async def _slow_lines():
        """Generator that hangs longer than idle_timeout on the first chunk."""
        await asyncio.sleep(5.0)
        yield "data: should not reach here"

    mock_response.aiter_lines = _slow_lines

    mock_client = MagicMock()
    mock_client.stream = MagicMock()
    mock_client.stream.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_client.stream.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        chunks = []
        async for chunk in _proxy_stream_generator(
            validated_body=_make_request(),
            request_id="req-idle-timeout-01",
            idle_timeout=0.01,  # 10 ms idle timeout — very short
            overall_timeout=10.0,
        ):
            chunks.append(chunk)

    all_content = "".join(chunks)
    assert (
        "event: error" in all_content
    ), f"Expected error frame on idle timeout; got: {all_content!r}"
    assert "data: [DONE]" not in all_content, "Stream must not emit [DONE] on idle timeout"


@pytest.mark.asyncio
async def test_stream_overall_timeout_emits_error_frame(settings_env):
    """Overall timeout (REQUEST_TIMEOUT_SECONDS) stops the stream with an error frame.

    MED-2 fix: asyncio.timeout(overall_timeout) wraps the entire generator.
    """
    from gateway.models import CreateChatCompletionRequest
    from gateway.upstream.openai_proxy import _proxy_stream_generator

    def _make_request() -> CreateChatCompletionRequest:
        return CreateChatCompletionRequest(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
        )

    mock_response = MagicMock()
    mock_response.status_code = 200

    async def _drip_lines():
        """Drip chunks slowly, each within idle_timeout, but total > overall_timeout."""
        for i in range(100):
            await asyncio.sleep(0.02)  # 20 ms between chunks (under idle_timeout=1s)
            chunk = (
                f'{{"id":"c{i}","object":"chat.completion.chunk",'
                '"created":1,"model":"m","choices":[]}}'
            )
            yield f"data: {chunk}"

    mock_response.aiter_lines = _drip_lines

    mock_client = MagicMock()
    mock_client.stream = MagicMock()
    mock_client.stream.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_client.stream.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        chunks = []
        async for chunk in _proxy_stream_generator(
            validated_body=_make_request(),
            request_id="req-overall-timeout-01",
            idle_timeout=1.0,  # 1s idle timeout — chunks are fast enough
            overall_timeout=0.05,  # 50 ms overall — will expire before all 100 chunks
        ):
            chunks.append(chunk)

    all_content = "".join(chunks)
    assert (
        "event: error" in all_content
    ), f"Expected error frame on overall timeout; got: {all_content!r}"
    assert "data: [DONE]" not in all_content, "Stream must not emit [DONE] on overall timeout"


# ---------------------------------------------------------------------------
# MED-3: Verify single request_id across request pipeline (additional check)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_event_request_id_matches_413_response(settings_env, monkeypatch):
    """The request_id in the audit event for a 413 matches the response X-Request-Id.

    MED-3: TerminalAuditMiddleware generates ONE canonical ID. The 413 response
    from RequestValidationMiddleware echoes it. The audit event also carries it.
    All three must be identical.
    """
    monkeypatch.setenv("MAX_BODY_BYTES", "50")
    _reset_settings()

    audit_repo, audit_patches = _make_audit_context()
    auth_patches = _make_auth_context()

    with auth_patches[0], auth_patches[1], audit_patches[0], audit_patches[1]:
        app = _create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            resp = await ac.post(
                "/v1/chat/completions",
                content=b"x" * 200,
                headers=_valid_headers(),
            )

    assert resp.status_code == 413
    rid_header = resp.headers.get("x-request-id")
    rid_body = resp.json().get("request_id")

    assert rid_header, "X-Request-Id header missing from 413 response"
    assert rid_body, "request_id missing from 413 response body"
    assert rid_header == rid_body, "Header and body request_id must match"

    audit_repo.append.assert_awaited_once()
    event = audit_repo.append.call_args[0][0]
    assert (
        event["request_id"] == rid_header
    ), "Audit event request_id must equal the X-Request-Id header"
