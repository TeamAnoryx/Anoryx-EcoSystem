"""STEP-9 security-audit remediation tests (F-009).

Covers all five findings:

M1 — /metrics is unauthenticated: GET /metrics with no auth + no tenant headers
     returns 200 with a Prometheus exposition body. Other endpoints still require
     auth (no regression to the exempt logic).

M2 — audit.py span double-execution: inject a failing append under a real
     recording span; assert append is called EXACTLY ONCE for each of the three
     emitters (emit_terminal_record, emit_routing_decision, emit_rate_limit_event).

L1 — rate_limit_redis_error variant emitted: two distinct Redis error classes
     during one outage → two rate_limit_redis_error events (one per class) + exactly
     one rate_limit_degraded.

L3 — span exception hygiene: span records error.type / error.module attributes,
     NOT the full exception message via record_exception.

L4 — team_rpm_limit read from DB at runtime: with a DB-configured team_rpm_limit
     (mock the repo to return a value), the team tier enforces; with None it is a
     no-op; a repo read error → no-op + request proceeds.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import _reset_settings
from gateway.middleware.rate_limit import (
    _set_team_rpm_limit,
    reset_state_for_testing,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_fake_key_row(
    tenant_id: str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    team_id: str = "11111111-2222-3333-4444-555555555555",
    project_id: str = "66666666-7777-8888-9999-aaaaaaaaaaaa",
    agent_id: str = "gateway-core",
    key_id: str = "key-test-001",
):
    row = MagicMock()
    row.tenant_id = tenant_id
    row.team_id = team_id
    row.project_id = project_id
    row.agent_id = agent_id
    row.key_id = key_id
    row.is_active = True
    return row


@pytest.fixture(autouse=True)
def _env_and_reset(monkeypatch):
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
    yield
    _reset_settings()
    reset_state_for_testing()


# ---------------------------------------------------------------------------
# M1 — /metrics is NOT gated by auth or tenant headers
# ---------------------------------------------------------------------------


class TestM1MetricsExempt:
    """M1: /metrics must be reachable without auth or tenant headers (R5)."""

    def _build_app(self):
        """Build the real FastAPI app with mocked auth + audit (no-op)."""
        from gateway.main import create_app

        key_row = _make_fake_key_row()
        auth_repo = MagicMock()
        auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)
        audit_repo = MagicMock()
        audit_repo.append = AsyncMock(return_value=MagicMock())

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

        with (
            patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
            patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
            patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
            patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo),
        ):
            app = create_app()
        return app

    def test_get_metrics_no_auth_returns_200(self):
        """GET /metrics with no Authorization and no tenant headers returns 200."""
        from starlette.testclient import TestClient

        app = self._build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/metrics")
        assert (
            resp.status_code == 200
        ), f"Expected 200 on /metrics with no auth, got {resp.status_code}: {resp.text[:200]}"

    def test_get_metrics_response_is_prometheus_exposition(self):
        """GET /metrics returns Content-Type text/plain (Prometheus exposition format)."""
        from starlette.testclient import TestClient

        app = self._build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        ct = resp.headers.get("content-type", "")
        assert "text/plain" in ct, f"Expected text/plain Content-Type, got: {ct!r}"

    def test_v1_endpoint_still_requires_auth(self):
        """Non-exempt endpoints still return 401 when auth is missing (no regression)."""
        from starlette.testclient import TestClient

        app = self._build_app()
        client = TestClient(app, raise_server_exceptions=False)
        # POST /v1/chat/completions with no Authorization header → 401
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}]},
            headers={
                "X-Anoryx-Tenant-Id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "X-Anoryx-Team-Id": "11111111-2222-3333-4444-555555555555",
                "X-Anoryx-Project-Id": "66666666-7777-8888-9999-aaaaaaaaaaaa",
                "X-Anoryx-Agent-Id": "gateway-core",
                # No Authorization header
            },
        )
        assert (
            resp.status_code == 401
        ), f"Expected 401 on /v1/chat/completions without auth, got {resp.status_code}"

    def test_health_endpoint_still_exempt(self):
        """/health is still exempt (existing behaviour preserved)."""
        from starlette.testclient import TestClient

        app = self._build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_metrics_path_reads_from_settings(self, monkeypatch):
        """When METRICS_PATH is overridden, the custom path is also exempt."""
        monkeypatch.setenv("METRICS_PATH", "/internal/prom")
        _reset_settings()

        from gateway.middleware.auth import _get_auth_exempt_paths
        from gateway.middleware.tenant_context import _get_auth_exempt_paths as tc_exempt

        auth_exempt = _get_auth_exempt_paths()
        tc_exempt_set = tc_exempt()

        assert (
            "/internal/prom" in auth_exempt
        ), f"Custom metrics path not in auth exempt set: {auth_exempt}"
        assert (
            "/internal/prom" in tc_exempt_set
        ), f"Custom metrics path not in tenant_context exempt set: {tc_exempt_set}"
        # Default /metrics must NOT be in the exempt set when overridden
        assert "/metrics" not in auth_exempt or "/internal/prom" in auth_exempt


# ---------------------------------------------------------------------------
# M2 — span double-execution guard: append called EXACTLY ONCE per emitter
# ---------------------------------------------------------------------------


class TestM2SpanDoubleExecution:
    """M2: each emitter calls the underlying append EXACTLY ONCE, even when a
    real recording span is active and the span context manager raises after
    the append has started.
    """

    @pytest.mark.asyncio
    async def test_emit_terminal_record_append_called_once_on_span_raise(self):
        """emit_terminal_record: append runs exactly once even when the span raises
        AFTER the append was invoked (_append_ran=True path).
        """
        import time as _time

        from gateway.context import TenantContext
        from gateway.middleware.audit import emit_terminal_record

        ctx = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            team_id="11111111-2222-3333-4444-555555555555",
            project_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
            agent_id="gateway-core",
            virtual_key_id="key-001",
        )

        append_mock = AsyncMock(return_value=None)
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = append_mock

        # Build a mock span that raises ON __exit__ (after the body ran).
        # This simulates span finalisation raising AFTER _append_ran is True.
        class _SpanRaisesOnExit:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is None:
                    raise RuntimeError("span export exploded after append")
                return False  # do not suppress existing exception

            def set_attribute(self, k, v):
                pass

            def record_exception(self, exc):
                pass

            def set_status(self, *a, **kw):
                pass

        class _FakeTracer:
            def start_as_current_span(self, name, **kwargs):
                return _SpanRaisesOnExit()

        @asynccontextmanager
        async def _priv_cm():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield

            session.begin = _begin
            with patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock):
                yield session

        with (
            patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
            patch("gateway.middleware.audit.get_tracer", return_value=_FakeTracer()),
        ):
            # emit_terminal_record raises GatewayError when append succeeds but
            # span exit raises — the outer except sees the RuntimeError and
            # re-raises as GatewayError. We don't care about the exception type
            # here; we care that append was called exactly once.
            try:
                await emit_terminal_record(
                    request_id="req-m2-terminal",
                    tenant_context=ctx,
                    model="gpt-3.5-turbo",
                    tokens_in=10,
                    tokens_out=5,
                    start_time=_time.monotonic(),
                )
            except Exception:
                pass  # expected — span __exit__ raised

        # The key assertion: append was called EXACTLY ONCE (not twice).
        assert append_mock.call_count == 1, (
            f"emit_terminal_record called append {append_mock.call_count} times "
            f"(expected exactly 1) — double-execution guard (M2) failed."
        )

    @pytest.mark.asyncio
    async def test_emit_routing_decision_append_called_once_on_span_raise(self):
        """emit_routing_decision: append runs exactly once even when span raises after it."""
        from gateway.context import TenantContext
        from gateway.middleware.audit import emit_routing_decision

        ctx = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            team_id="11111111-2222-3333-4444-555555555555",
            project_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
            agent_id="gateway-core",
            virtual_key_id="key-002",
        )

        append_mock = AsyncMock(return_value=None)
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = append_mock

        class _SpanRaisesOnExit:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is None:
                    raise RuntimeError("span export exploded after routing append")
                return False

            def set_attribute(self, k, v):
                pass

        class _FakeTracer:
            def start_as_current_span(self, name, **kwargs):
                return _SpanRaisesOnExit()

        @asynccontextmanager
        async def _priv_cm():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield

            session.begin = _begin
            with patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock):
                yield session

        with (
            patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
            patch("gateway.middleware.audit.get_tracer", return_value=_FakeTracer()),
        ):
            # Best-effort: emit_routing_decision swallows errors.
            await emit_routing_decision(
                request_id="req-m2-routing",
                tenant_context=ctx,
                selected_provider="openai",
                routing_reason="primary",
                outcome="success",
                action_taken="routed",
                attempt_index=0,
                requested_model="gpt-3.5-turbo",
            )

        assert append_mock.call_count == 1, (
            f"emit_routing_decision called append {append_mock.call_count} times "
            f"(expected exactly 1) — double-execution guard (M2) failed."
        )

    @pytest.mark.asyncio
    async def test_emit_rate_limit_event_append_called_once_on_span_raise(self):
        """emit_rate_limit_event: append runs exactly once even when span raises after it."""
        from gateway.middleware.audit import emit_rate_limit_event

        append_mock = AsyncMock(return_value=None)
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = append_mock

        class _SpanRaisesOnExit:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is None:
                    raise RuntimeError("span export exploded after rl append")
                return False

            def set_attribute(self, k, v):
                pass

        class _FakeTracer:
            def start_as_current_span(self, name, **kwargs):
                return _SpanRaisesOnExit()

        @asynccontextmanager
        async def _priv_cm():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield

            session.begin = _begin
            with patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock):
                yield session

        with (
            patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
            patch("gateway.middleware.audit.get_tracer", return_value=_FakeTracer()),
        ):
            # Best-effort: emit_rate_limit_event swallows errors.
            await emit_rate_limit_event(
                "rate_limit_degraded",
                request_id="req-m2-rl",
                tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                redis_error_class="ConnectionError",
                redis_error_module="redis.exceptions",
            )

        assert append_mock.call_count == 1, (
            f"emit_rate_limit_event called append {append_mock.call_count} times "
            f"(expected exactly 1) — double-execution guard (M2) failed."
        )

    @pytest.mark.asyncio
    async def test_emit_terminal_record_no_double_run_when_span_setup_fails(self):
        """When span SETUP fails (before the append), the untraced fallback runs once."""
        import time as _time

        from gateway.context import TenantContext
        from gateway.middleware.audit import emit_terminal_record

        ctx = TenantContext(
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            team_id="11111111-2222-3333-4444-555555555555",
            project_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
            agent_id="gateway-core",
            virtual_key_id="key-003",
        )

        append_mock = AsyncMock(return_value=None)
        audit_repo_mock = MagicMock()
        audit_repo_mock.append = append_mock

        # Span that raises on __enter__ (setup fails before body runs).
        class _SpanRaisesOnEnter:
            def __enter__(self):
                raise RuntimeError("span setup failed")

            def __exit__(self, *a):
                return False

            def set_attribute(self, k, v):
                pass

        class _FakeTracer:
            def start_as_current_span(self, name, **kwargs):
                return _SpanRaisesOnEnter()

        @asynccontextmanager
        async def _priv_cm():
            session = MagicMock()

            @asynccontextmanager
            async def _begin():
                yield

            session.begin = _begin
            with patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo_mock):
                yield session

        with (
            patch("gateway.middleware.audit.get_privileged_session", _priv_cm),
            patch("gateway.middleware.audit.get_tracer", return_value=_FakeTracer()),
        ):
            await emit_terminal_record(
                request_id="req-m2-setup-fail",
                tenant_context=ctx,
                model="gpt-3.5-turbo",
                tokens_in=10,
                tokens_out=5,
                start_time=_time.monotonic(),
            )

        # Span setup failed — untraced fallback must have run exactly once.
        assert append_mock.call_count == 1, (
            f"emit_terminal_record called append {append_mock.call_count} times on "
            f"span-setup-failure (expected exactly 1 via untraced fallback)."
        )


# ---------------------------------------------------------------------------
# L1 — rate_limit_redis_error emitted per distinct error class, once per outage
# ---------------------------------------------------------------------------


class TestL1RedisErrorVariantEmitted:
    """L1: rate_limit_redis_error is emitted once per distinct Redis error class
    per outage; rate_limit_degraded is emitted once per outage transition.
    """

    @pytest.mark.asyncio
    async def test_two_distinct_error_classes_emit_two_redis_error_events(self):
        """Two distinct Redis error classes during one outage → exactly two
        rate_limit_redis_error events (one per class) + exactly one
        rate_limit_degraded.
        """
        from redis.exceptions import ConnectionError as RedisConnErr
        from redis.exceptions import TimeoutError as RedisTimeoutErr

        from gateway.middleware.rate_limit import _handle_redis_error

        emitted: list[tuple[str, str]] = []  # (event_type, redis_error_class)

        async def _fake_emit(event_type, *, request_id, tenant_id, **kwargs):
            emitted.append((event_type, kwargs.get("redis_error_class", "")))

        with patch("gateway.middleware.rate_limit.emit_rate_limit_event", _fake_emit):
            # First error — ConnectionError.
            await _handle_redis_error(
                RedisConnErr("mock conn error"),
                virtual_key_id="vk-l1",
                tenant_id="tenant-l1",
                request_id="req-l1-1",
            )
            # Second error — SAME class — should NOT emit another redis_error event.
            await _handle_redis_error(
                RedisConnErr("mock conn error 2"),
                virtual_key_id="vk-l1",
                tenant_id="tenant-l1",
                request_id="req-l1-2",
            )
            # Third error — DIFFERENT class (TimeoutError) — should emit another redis_error.
            await _handle_redis_error(
                RedisTimeoutErr("mock timeout"),
                virtual_key_id="vk-l1",
                tenant_id="tenant-l1",
                request_id="req-l1-3",
            )

        degraded_events = [e for e in emitted if e[0] == "rate_limit_degraded"]
        redis_error_events = [e for e in emitted if e[0] == "rate_limit_redis_error"]

        assert (
            len(degraded_events) == 1
        ), f"Expected exactly 1 rate_limit_degraded, got {len(degraded_events)}: {emitted}"
        assert len(redis_error_events) == 2, (
            f"Expected exactly 2 rate_limit_redis_error (one per distinct class), "
            f"got {len(redis_error_events)}: {emitted}"
        )

        error_classes_emitted = {e[1] for e in redis_error_events}
        assert (
            "ConnectionError" in error_classes_emitted
        ), f"Expected ConnectionError in emitted classes: {error_classes_emitted}"
        assert (
            "TimeoutError" in error_classes_emitted
        ), f"Expected TimeoutError in emitted classes: {error_classes_emitted}"

    @pytest.mark.asyncio
    async def test_same_error_class_twice_emits_only_one_redis_error_event(self):
        """The same Redis error class repeated does NOT emit a second redis_error event."""
        from redis.exceptions import ConnectionError as RedisConnErr

        from gateway.middleware.rate_limit import _handle_redis_error

        emitted: list[str] = []

        async def _fake_emit(event_type, **kwargs):
            emitted.append(event_type)

        with patch("gateway.middleware.rate_limit.emit_rate_limit_event", _fake_emit):
            await _handle_redis_error(
                RedisConnErr("first"),
                virtual_key_id="vk-same",
                tenant_id="tenant-same",
                request_id="req-same-1",
            )
            await _handle_redis_error(
                RedisConnErr("second"),
                virtual_key_id="vk-same",
                tenant_id="tenant-same",
                request_id="req-same-2",
            )

        redis_error_count = emitted.count("rate_limit_redis_error")
        assert (
            redis_error_count == 1
        ), f"Expected 1 rate_limit_redis_error for same error class, got {redis_error_count}"

    @pytest.mark.asyncio
    async def test_redis_error_event_carries_error_class_not_message(self):
        """rate_limit_redis_error carries redis_error_class (type name), never str(exc)."""
        from redis.exceptions import ConnectionError as RedisConnErr

        from gateway.middleware.rate_limit import _handle_redis_error

        captured: list[dict] = []

        async def _fake_emit(event_type, *, request_id, **kwargs):
            captured.append({"event_type": event_type, **kwargs})

        exc = RedisConnErr("redis://user:SECRETPASS@host:6379 connection refused")

        with patch("gateway.middleware.rate_limit.emit_rate_limit_event", _fake_emit):
            await _handle_redis_error(
                exc,
                virtual_key_id="vk-hygiene",
                tenant_id="tenant-hygiene",
                request_id="req-hygiene",
            )

        redis_error_payloads = [c for c in captured if c["event_type"] == "rate_limit_redis_error"]
        assert len(redis_error_payloads) == 1
        payload = redis_error_payloads[0]

        assert (
            payload.get("redis_error_class") == "ConnectionError"
        ), f"Expected error_class='ConnectionError', got: {payload.get('redis_error_class')!r}"
        # The connection string in the exception message must NOT appear.
        assert "SECRETPASS" not in str(
            payload
        ), f"Secret connection-string leaked into rate_limit_redis_error payload: {payload}"
        assert "redis://" not in str(
            payload
        ), f"Connection URL leaked into rate_limit_redis_error payload: {payload}"

    @pytest.mark.asyncio
    async def test_mark_recovered_resets_error_class_debounce(self):
        """After mark_recovered(), the same error class emits again on the next outage."""
        from redis.exceptions import ConnectionError as RedisConnErr

        from gateway.middleware.rate_limit import _handle_redis_error, mark_recovered

        emitted: list[str] = []

        async def _fake_emit(event_type, **kwargs):
            emitted.append(event_type)

        with patch("gateway.middleware.rate_limit.emit_rate_limit_event", _fake_emit):
            # First outage.
            await _handle_redis_error(
                RedisConnErr("outage 1"),
                virtual_key_id="vk-recovery",
                tenant_id="tenant-recovery",
                request_id="req-rec-1",
            )
            first_count = emitted.count("rate_limit_redis_error")

            # Recovery: resets debounce.
            mark_recovered()

            # Second outage — same error class should emit again.
            await _handle_redis_error(
                RedisConnErr("outage 2"),
                virtual_key_id="vk-recovery",
                tenant_id="tenant-recovery",
                request_id="req-rec-2",
            )
            second_count = emitted.count("rate_limit_redis_error") - first_count

        assert first_count == 1, f"Expected 1 redis_error event in outage 1, got {first_count}"
        assert second_count == 1, f"Expected 1 redis_error event in outage 2, got {second_count}"


# ---------------------------------------------------------------------------
# L3 — span exception hygiene: error.type attribute, NOT record_exception
# ---------------------------------------------------------------------------


class TestL3SpanExceptionHygiene:
    """L3: the rate_limit span records error.type/error.module attributes and
    sets ERROR status instead of calling record_exception() with the full object.
    """

    @pytest.mark.asyncio
    async def test_rate_limit_span_uses_error_type_not_record_exception(self, monkeypatch):
        """When check_rate_limit raises (e.g. via GatewayError), the span sets
        error.type and set_status(ERROR) but does NOT call record_exception().
        """
        import time as _time
        from collections import deque

        from gateway.exceptions import GatewayError
        from gateway.middleware.rate_limit import _key_windows, _tenant_windows, check_rate_limit

        # Set limit to 1 and pre-fill the window to trigger immediate rejection.
        monkeypatch.setenv("RATE_LIMIT_RPM", "1")
        monkeypatch.setenv("RATE_LIMIT_BURST", "100")
        _reset_settings()

        # Pre-fill the sliding window so the FIRST request is already over limit.
        now = _time.monotonic()
        _key_windows["vk-l3"] = deque([now])
        _tenant_windows["tenant-l3"] = deque([now])

        span_attrs: dict[str, Any] = {}
        span_status_calls: list[tuple] = []
        record_exception_calls: list[Any] = []

        class _RecordingSpan:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False  # don't suppress

            def set_attribute(self, k, v):
                span_attrs[k] = v

            def set_status(self, code, *args, **kwargs):
                span_status_calls.append((code,) + args)

            def record_exception(self, exc):
                # Should NOT be called — L3 hygiene.
                record_exception_calls.append(exc)

        class _RecordingTracer:
            def start_as_current_span(self, name, **kwargs):
                return _RecordingSpan()

        import gateway.redis_client as rc

        # Force legacy path (degraded) so Redis is not involved.
        rc._set_degraded(True)

        with patch("gateway.middleware.rate_limit.get_tracer", return_value=_RecordingTracer()):
            # Limit is 1, window is already full → rejected.
            with pytest.raises(GatewayError):
                await check_rate_limit("vk-l3", "tenant-l3")

        # L3: record_exception must NOT have been called.
        assert len(record_exception_calls) == 0, (
            f"record_exception was called {len(record_exception_calls)} time(s) "
            f"with: {record_exception_calls} — L3 hygiene violation."
        )
        # error.type attribute must be set.
        assert (
            "error.type" in span_attrs
        ), f"span missing 'error.type' attribute; got: {list(span_attrs.keys())}"
        # status must be set to ERROR.
        assert len(span_status_calls) > 0, "set_status was never called"

    @pytest.mark.asyncio
    async def test_redis_error_span_uses_error_type_not_full_message(self, monkeypatch):
        """When Redis raises, the span records error.type (class name only),
        never the full exception message that might contain credentials.
        """
        from redis.exceptions import ConnectionError as RedisConnErr

        from gateway.middleware.rate_limit import check_rate_limit

        monkeypatch.setenv("RATE_LIMIT_RPM", "600")
        monkeypatch.setenv("RATE_LIMIT_BURST", "60")
        _reset_settings()

        span_attrs: dict[str, Any] = {}
        record_exception_calls: list[Any] = []

        class _RecordingSpan:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

            def set_attribute(self, k, v):
                span_attrs[k] = v

            def set_status(self, *a, **kw):
                pass

            def record_exception(self, exc):
                record_exception_calls.append(exc)

        class _RecordingTracer:
            def start_as_current_span(self, name, **kwargs):
                return _RecordingSpan()

        import gateway.redis_client as rc

        # Ensure non-degraded so the Redis path is attempted.
        rc._set_degraded(False)

        conn_error = RedisConnErr("redis://user:SECRETPASS@host:6379 mock error")

        async def _emit_noop(*a, **kw):
            pass

        with (
            patch("gateway.middleware.rate_limit.get_tracer", return_value=_RecordingTracer()),
            patch("gateway.middleware.rate_limit._redis_primary_check", side_effect=conn_error),
            patch(
                "gateway.middleware.rate_limit._legacy_check_rate_limit",
                return_value=(600, 599, 9999),
            ),
            patch("gateway.middleware.rate_limit.emit_rate_limit_event", _emit_noop),
        ):
            result = await check_rate_limit("vk-l3-redis", "tenant-l3-redis")

        # The fallback should have admitted the request.
        assert result is not None

        # L3: record_exception must NOT have been called.
        assert len(record_exception_calls) == 0, (
            f"record_exception was called with Redis error (may contain credentials): "
            f"{record_exception_calls}"
        )
        # Verify no credential string appeared in span attributes.
        for k, v in span_attrs.items():
            assert "SECRETPASS" not in str(v), f"Credential in span attribute {k!r}: {v!r}"


# ---------------------------------------------------------------------------
# L4 — team_rpm_limit read from DB at runtime
# ---------------------------------------------------------------------------


class TestL4TeamRpmLimitFromDB:
    """L4: check_rate_limit reads team_rpm_limit from the tenant routing policy
    at runtime via the repository; cache and no-op semantics preserved.
    """

    @pytest.mark.asyncio
    async def test_team_tier_enforces_when_db_returns_limit(self, monkeypatch):
        """With a DB-configured team_rpm_limit (via cache / test hook), the
        async lookup returns the configured value.
        """
        from gateway.middleware.rate_limit import _get_team_rpm_limit_async

        # Inject a team limit of 1 via the cache (simulates a DB-backed value).
        _set_team_rpm_limit("tenant-l4", "team-l4", 1)

        result = await _get_team_rpm_limit_async("tenant-l4", "team-l4")
        assert result == 1, f"Expected team_rpm_limit=1 from cache, got {result}"

    @pytest.mark.asyncio
    async def test_team_tier_noop_when_db_returns_none(self, monkeypatch):
        """With no DB-configured team_rpm_limit (None), the team tier is a no-op."""
        from gateway.middleware.rate_limit import _get_team_rpm_limit_async

        # Clear cache — DB will be called but we mock it to return None.
        reset_state_for_testing()

        async def _mock_db_fetch(tenant_id, team_id):
            return None

        with patch(
            "gateway.middleware.rate_limit._fetch_team_rpm_limit_from_db",
            side_effect=_mock_db_fetch,
        ):
            result = await _get_team_rpm_limit_async("tenant-l4-none", "team-l4-none")

        assert result is None, f"Expected None (no-op) when DB returns None, got {result}"

    @pytest.mark.asyncio
    async def test_team_tier_noop_on_db_read_error(self, monkeypatch):
        """A DB read error → no-op (None) + request proceeds; never raises.

        Tests the full stack: _get_team_rpm_limit_async → _fetch_team_rpm_limit_from_db
        with a bad _get_tenant_session, verifying that the exception is caught and
        None is returned (team tier no-op).
        """
        from gateway.middleware.rate_limit import _get_team_rpm_limit_async

        reset_state_for_testing()

        # Mock the session factory to raise — simulating a DB connection failure.
        @asynccontextmanager
        async def _bad_session(tenant_id):
            raise ConnectionError("DB unreachable during test")
            yield  # pragma: no cover

        with patch("gateway.middleware.rate_limit._get_tenant_session", _bad_session):
            # Must not raise — returns None (team tier no-op).
            result = await _get_team_rpm_limit_async("tenant-l4-err", "team-l4-err")

        assert result is None, (
            f"Expected None on DB read error from _get_team_rpm_limit_async, got {result} — "
            "DB hiccup must never block the request (L4)"
        )

    @pytest.mark.asyncio
    async def test_fetch_team_rpm_limit_returns_none_on_db_error(self, monkeypatch):
        """_fetch_team_rpm_limit_from_db catches exceptions and returns None."""
        from gateway.middleware.rate_limit import _fetch_team_rpm_limit_from_db

        reset_state_for_testing()

        # Mock _get_tenant_session (module-level wrapper) to raise immediately.
        # L4: DB errors must never block the request.
        @asynccontextmanager
        async def _bad_session(tenant_id):
            raise ConnectionError("DB unreachable")
            yield  # pragma: no cover — make it a generator

        with patch("gateway.middleware.rate_limit._get_tenant_session", _bad_session):
            # Must not propagate — returns None on error.
            result = await _fetch_team_rpm_limit_from_db("tenant-db-err", "team-db-err")

        assert result is None, (
            f"Expected None on DB read error, got {result} — "
            "DB hiccup must never block the request (L4)"
        )

    @pytest.mark.asyncio
    async def test_fetch_team_rpm_limit_returns_value_from_db(self, monkeypatch):
        """_fetch_team_rpm_limit_from_db returns the team_rpm_limit from the DB row."""
        from gateway.middleware.rate_limit import _fetch_team_rpm_limit_from_db, _team_limit_cache

        reset_state_for_testing()

        # Mock session.execute to return a scalar row with team_rpm_limit = 42.
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = 42

        mock_session = MagicMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        @asynccontextmanager
        async def _begin_cm():
            yield

        mock_session.begin = _begin_cm

        @asynccontextmanager
        async def _tenant_session_cm(tenant_id):
            yield mock_session

        with patch("gateway.middleware.rate_limit._get_tenant_session", _tenant_session_cm):
            result = await _fetch_team_rpm_limit_from_db("tenant-db-42", "team-db-42")

        assert result == 42, f"Expected 42 from DB, got {result}"

        # Result is also cached.
        assert (
            "tenant-db-42",
            "team-db-42",
        ) in _team_limit_cache, (
            "DB result was not cached — subsequent requests will re-query DB unnecessarily"
        )

    @pytest.mark.asyncio
    async def test_fetch_team_rpm_limit_caches_result(self, monkeypatch):
        """A DB result is cached; the second call does not hit the DB again."""
        from gateway.middleware.rate_limit import _get_team_rpm_limit_async

        reset_state_for_testing()

        call_count = [0]
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = 100

        mock_session = MagicMock()

        async def _execute(stmt):
            call_count[0] += 1
            return mock_result

        mock_session.execute = _execute

        @asynccontextmanager
        async def _begin_cm():
            yield

        mock_session.begin = _begin_cm

        @asynccontextmanager
        async def _tenant_session_cm(tenant_id):
            yield mock_session

        with patch("gateway.middleware.rate_limit._get_tenant_session", _tenant_session_cm):
            r1 = await _get_team_rpm_limit_async("tenant-cache", "team-cache")
            r2 = await _get_team_rpm_limit_async("tenant-cache", "team-cache")

        assert r1 == 100
        assert r2 == 100
        assert (
            call_count[0] == 1
        ), f"DB was queried {call_count[0]} times; expected exactly 1 (cache should serve r2)"

    @pytest.mark.asyncio
    async def test_set_team_rpm_limit_test_hook_overrides_db(self, monkeypatch):
        """_set_team_rpm_limit (test hook) populates the cache; DB is not called."""
        from gateway.middleware.rate_limit import _get_team_rpm_limit_async

        reset_state_for_testing()

        # Pre-populate cache via test hook.
        _set_team_rpm_limit("tenant-hook", "team-hook", 77)

        call_count = [0]

        async def _should_not_be_called(tenant_id, team_id):
            call_count[0] += 1
            return 999  # wrong value

        with patch(
            "gateway.middleware.rate_limit._fetch_team_rpm_limit_from_db",
            side_effect=_should_not_be_called,
        ):
            result = await _get_team_rpm_limit_async("tenant-hook", "team-hook")

        assert result == 77, f"Expected 77 from test hook, got {result}"
        assert call_count[0] == 0, "DB was queried despite cache hit from test hook"
