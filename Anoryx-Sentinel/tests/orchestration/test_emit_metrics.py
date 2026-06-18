"""Tests for F-009 STEP 3b: Prometheus metric instrumentation in HookContext.emit().

Covers:
  1. record_event() is called on every emit() with the correct event_type and
     tenant_id, regardless of whether the audit append succeeds.
  2. A forced audit-append failure triggers record_audit_write_failure(component=
     detector_slug) and emit() still returns False (no raise — semantics unchanged).
  3. A metrics failure (record_event raises) is fully swallowed — emit() still
     completes normally and returns True.
  4. record_event() is called BEFORE the budget check, so a budget-exhausted emit
     still increments the metric (security occurrence is always counted).
  5. judge_outcome is preferred over outcome when constructing the record_event call.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.context import TenantContext
from orchestration.context import HookContext

# ---------------------------------------------------------------------------
# Synthetic test IDs (no real PII — purely synthetic UUIDs)
# ---------------------------------------------------------------------------
_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-000000000099"
_TEAM_ID = "11111111-2222-3333-4444-000000000099"
_PROJECT_ID = "66666666-7777-8888-9999-000000000099"
_AGENT_ID = "test-agent"
_KEY_ID = "vk-00000000000000000000000000000099"
_REQUEST_ID = "req-00000000000000000000000000000099"

_PII_EVENT = {
    "event_type": "pii_blocked",
    "pattern_name": "email",
    "severity": "low",
    "action_taken": "masked",
}
_DETECTOR = "data-protection"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_tenant_context() -> TenantContext:
    return TenantContext(
        tenant_id=_TENANT_ID,
        team_id=_TEAM_ID,
        project_id=_PROJECT_ID,
        agent_id=_AGENT_ID,
        virtual_key_id=_KEY_ID,
    )


def _make_hook_context(cap: int = 10) -> HookContext:
    return HookContext(
        tenant_context=_make_tenant_context(),
        request_id=_REQUEST_ID,
        original_user_content="hello",
        phase="pre_request",
        _events_per_detector_cap=cap,
    )


def _good_session_patch():
    """Return a context-manager factory that patches get_privileged_session to succeed."""

    @asynccontextmanager
    async def _cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    return _cm


# ---------------------------------------------------------------------------
# Test 1: record_event called with correct event_type and tenant_id on success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_calls_record_event_with_event_type_and_tenant_id():
    """emit() calls metrics.record_event with the event's event_type and tenant_id."""
    ctx = _make_hook_context()

    fake_repo = MagicMock()
    fake_repo.append = AsyncMock(return_value=MagicMock())

    with (
        patch("orchestration.context.get_privileged_session", _good_session_patch()),
        patch("orchestration.context.AuditLogRepository", return_value=fake_repo),
        patch("gateway.observability.metrics.record_event") as mock_record_event,
    ):
        result = await ctx.emit(_PII_EVENT, detector_slug=_DETECTOR)

    assert result is True
    mock_record_event.assert_called_once()
    call_kwargs = mock_record_event.call_args
    # Positional arg: event_type
    assert call_kwargs.args[0] == "pii_blocked"
    # Keyword arg: tenant_id
    assert call_kwargs.kwargs["tenant_id"] == _TENANT_ID


# ---------------------------------------------------------------------------
# Test 2: forced append failure triggers record_audit_write_failure; emit -> False
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_append_failure_triggers_audit_write_failure_metric():
    """A forced audit append failure calls record_audit_write_failure(component=detector_slug)
    and emit() returns False (never raises — semantics unchanged)."""
    ctx = _make_hook_context()

    # Patch AuditLogRepository.append to raise so the except branch fires.
    fake_repo = MagicMock()
    fake_repo.append = AsyncMock(side_effect=RuntimeError("db is down"))

    with (
        patch("orchestration.context.get_privileged_session", _good_session_patch()),
        patch("orchestration.context.AuditLogRepository", return_value=fake_repo),
        patch("gateway.observability.metrics.record_event") as mock_record_event,
        patch("gateway.observability.metrics.record_audit_write_failure") as mock_audit_fail,
    ):
        result = await ctx.emit(_PII_EVENT, detector_slug=_DETECTOR)

    # emit() must return False — semantics unchanged.
    assert result is False

    # record_event was still called (before the append attempt).
    mock_record_event.assert_called_once()

    # record_audit_write_failure was called with component=detector_slug.
    mock_audit_fail.assert_called_once_with(component=_DETECTOR)


# ---------------------------------------------------------------------------
# Test 3: metrics failure is fully swallowed — emit() still succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_metrics_failure_is_swallowed():
    """If record_event raises, emit() swallows the error and returns True normally."""
    ctx = _make_hook_context()

    fake_repo = MagicMock()
    fake_repo.append = AsyncMock(return_value=MagicMock())

    with (
        patch("orchestration.context.get_privileged_session", _good_session_patch()),
        patch("orchestration.context.AuditLogRepository", return_value=fake_repo),
        patch(
            "gateway.observability.metrics.record_event",
            side_effect=RuntimeError("prometheus is down"),
        ),
    ):
        # Must not raise; must return True (append succeeded).
        result = await ctx.emit(_PII_EVENT, detector_slug=_DETECTOR)

    assert result is True


# ---------------------------------------------------------------------------
# Test 4: record_event fires even when budget is exhausted (before budget check)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_record_event_fires_before_budget_check():
    """record_event() is called even when the event budget is exhausted (cap=0).

    This verifies the metric increment is positioned before the budget_exhausted
    guard so security occurrences are always counted.
    """
    # cap=0 means budget is immediately exhausted — no append will happen.
    ctx = _make_hook_context(cap=0)

    with patch("gateway.observability.metrics.record_event") as mock_record_event:
        result = await ctx.emit(_PII_EVENT, detector_slug=_DETECTOR)

    # Budget exhausted → emit returns False (event dropped, no append).
    assert result is False
    # But record_event was still called once.
    mock_record_event.assert_called_once()
    assert mock_record_event.call_args.args[0] == "pii_blocked"


# ---------------------------------------------------------------------------
# Test 5: outcome field — judge_outcome preferred over outcome
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_passes_judge_outcome_to_record_event():
    """judge_outcome is preferred over outcome when building the record_event call."""
    ctx = _make_hook_context()

    judge_event = {
        "event_type": "judge_billing_event",
        "judge_preset": "injection-v1",
        "judge_outcome": "injection_detected",
        "outcome": "would-be-ignored",
    }

    fake_repo = MagicMock()
    fake_repo.append = AsyncMock(return_value=MagicMock())

    with (
        patch("orchestration.context.get_privileged_session", _good_session_patch()),
        patch("orchestration.context.AuditLogRepository", return_value=fake_repo),
        patch("gateway.observability.metrics.record_event") as mock_record_event,
    ):
        await ctx.emit(judge_event, detector_slug="defense")

    mock_record_event.assert_called_once()
    call_kwargs = mock_record_event.call_args
    assert call_kwargs.args[0] == "judge_billing_event"
    assert call_kwargs.kwargs["preset"] == "injection-v1"
    # judge_outcome is non-None so it takes precedence over outcome.
    assert call_kwargs.kwargs["outcome"] == "injection_detected"
