"""Tests for shadow_ai_detector module (F-005, ADR-0007 §13).

Covers (spec test list):
  - Emission gated on SHADOW_AI_EMISSION_ENABLED (default false → no event).
  - When enabled, emit_shadow_ai_event() produces a valid event.
  - detected_endpoint stripped of query/fragment/userinfo.
  - shadow_ai_detected event contract conformance (schema-validated).
  - Honest no-detection test: module confirms it does NOT detect shadow AI traffic.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import jsonschema
import pytest

from orchestration.config import _reset_orchestration_settings

_EVENTS_SCHEMA = json.loads(
    (Path(__file__).parent.parent.parent / "contracts" / "events.schema.json")
    .read_text(encoding="utf-8")
)
_VALIDATOR = jsonschema.Draft202012Validator(_EVENTS_SCHEMA)


# ---------------------------------------------------------------------------
# Gate: default false → no emission
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shadow_ai_gated_off_by_default(mock_hook_context, monkeypatch):
    """With SHADOW_AI_EMISSION_ENABLED=false, no event is emitted."""
    monkeypatch.setenv("SHADOW_AI_EMISSION_ENABLED", "false")
    _reset_orchestration_settings()

    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_event

    result = await emit_shadow_ai_event(
        context=mock_hook_context,
        detected_endpoint="example.com/api",
        traffic_volume=1,
    )
    assert result is False
    mock_hook_context.emit.assert_not_called()


@pytest.mark.asyncio
async def test_shadow_ai_enabled_emits(mock_hook_context, monkeypatch):
    """With SHADOW_AI_EMISSION_ENABLED=true, a valid event is emitted."""
    monkeypatch.setenv("SHADOW_AI_EMISSION_ENABLED", "true")
    _reset_orchestration_settings()

    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_event

    mock_hook_context.emit.return_value = True

    result = await emit_shadow_ai_event(
        context=mock_hook_context,
        detected_endpoint="api.shadow-ai.internal/v1/chat",
        traffic_volume=42,
    )
    assert result is True
    mock_hook_context.emit.assert_called_once()
    event = mock_hook_context.emit.call_args[0][0]
    assert event["event_type"] == "shadow_ai_detected"
    assert event["traffic_volume"] == 42
    assert "first_seen_at" in event


# ---------------------------------------------------------------------------
# Endpoint sanitization
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shadow_ai_strips_query_string(mock_hook_context, monkeypatch):
    """Query string is stripped from detected_endpoint before emission."""
    monkeypatch.setenv("SHADOW_AI_EMISSION_ENABLED", "true")
    _reset_orchestration_settings()

    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_event

    mock_hook_context.emit.return_value = True

    await emit_shadow_ai_event(
        context=mock_hook_context,
        detected_endpoint="api.example.com/v1?key=secret&foo=bar",
        traffic_volume=1,
    )
    event = mock_hook_context.emit.call_args[0][0]
    assert "?" not in event["detected_endpoint"]
    assert "key=secret" not in event["detected_endpoint"]


@pytest.mark.asyncio
async def test_shadow_ai_strips_fragment(mock_hook_context, monkeypatch):
    monkeypatch.setenv("SHADOW_AI_EMISSION_ENABLED", "true")
    _reset_orchestration_settings()

    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_event

    mock_hook_context.emit.return_value = True

    await emit_shadow_ai_event(
        context=mock_hook_context,
        detected_endpoint="api.example.com/path#section",
        traffic_volume=1,
    )
    event = mock_hook_context.emit.call_args[0][0]
    assert "#" not in event["detected_endpoint"]


@pytest.mark.asyncio
async def test_shadow_ai_invalid_endpoint_rejected(mock_hook_context, monkeypatch):
    """Endpoint that still contains forbidden chars after stripping → rejected."""
    monkeypatch.setenv("SHADOW_AI_EMISSION_ENABLED", "true")
    _reset_orchestration_settings()

    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_event

    result = await emit_shadow_ai_event(
        context=mock_hook_context,
        detected_endpoint="",  # empty after stripping
        traffic_volume=1,
    )
    assert result is False
    mock_hook_context.emit.assert_not_called()


# ---------------------------------------------------------------------------
# schema contract conformance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shadow_ai_event_contract_conformance(tenant_context, monkeypatch):
    """Stamped shadow_ai_detected event validates against events.schema.json."""
    monkeypatch.setenv("SHADOW_AI_EMISSION_ENABLED", "true")
    _reset_orchestration_settings()

    from orchestration.context import HookContext
    from orchestration.detectors.shadow_ai_detector import emit_shadow_ai_event

    emitted = []

    async def fake_emit(event, *, detector_slug):
        import uuid as _uuid
        from datetime import UTC, datetime

        stamped = dict(event)
        stamped["tenant_id"] = tenant_context.tenant_id
        stamped["team_id"] = tenant_context.team_id
        stamped["project_id"] = tenant_context.project_id
        stamped["agent_id"] = detector_slug
        stamped["event_id"] = str(_uuid.uuid4())
        stamped["event_timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        stamped["request_id"] = "req-0000000000000005"
        emitted.append(stamped)
        return True

    ctx = HookContext(
        tenant_context=tenant_context,
        request_id="req-0000000000000005",
        original_user_content="",
        phase="pre_request",
        _events_per_detector_cap=10,
    )
    ctx.emit = fake_emit  # type: ignore[method-assign]

    result = await emit_shadow_ai_event(
        context=ctx,
        detected_endpoint="shadow.ai.internal/v1/completions",
        traffic_volume=100,
        first_seen_at="2026-06-16T12:00:00Z",
    )
    assert result is True
    assert emitted, "No event emitted"
    ev = emitted[0]
    errors = list(_VALIDATOR.iter_errors(ev))
    assert not errors, f"Schema validation errors: {errors}"


# ---------------------------------------------------------------------------
# Honest no-detection: module does NOT detect shadow AI traffic
# ---------------------------------------------------------------------------


def test_shadow_ai_does_not_detect_traffic():
    """F-005 shadow_ai_detector contains NO real traffic detection.

    This test documents the honest scope: the module only provides an
    emission primitive.  It cannot detect shadow-AI traffic because it
    has no network egress monitoring, DNS inspection, or traffic analysis.
    Real detection is deferred to F-007.

    We verify that the module docstring explicitly states this (honest language).
    """
    import orchestration.detectors.shadow_ai_detector as mod

    docstring = (mod.__doc__ or "").lower()
    assert "does not detect" in docstring or "no real" in docstring or "emission primitive" in docstring, (
        "Module docstring must honestly state F-005 does not detect shadow AI traffic."
    )
